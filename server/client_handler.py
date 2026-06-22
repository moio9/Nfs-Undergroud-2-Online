"""
client_handler.py — Per-client TCP command processor.
Parses the stock LAN bootstrap (@tic/@dir) and the EA key=value protocol.
"""

import time
import threading
import logging
import struct
import socket
import ipaddress
from hashlib import md5
from typing import TYPE_CHECKING

from protocol import parse_message, encode_message, encode_error
from protocol import encode_user_record, encode_room_record, encode_game_record
from protocol import encode_master_stat
from user_manager import User, STAT_LOBBY, STAT_ROOM, STAT_GAME, STAT_IDLE
from matchmaking import MatchCriteria
from batch import GameReport, Challenge

if TYPE_CHECKING:
    from server import GameServer

log = logging.getLogger("client")


_TIC_REPLY = bytes.fromhex(
    "40 74 69 63 00 00 00 00 00 00 00 60"
    " 05 8b 21 84 ed 79 53 92 e6 29 fd f9 2d 24 da 9d 99 87 cd ec"
    " 92 11 5c 01 6c 8f ac 8d 72 94 a6 6a 5d a0 17 8d 3d 19 94 93"
    " a3 4b 39 6c 4b 21 05 0b 73 d3 08 7b ea b5 03 ea 7d d9 39 03"
    " 27 2e 0d 96 2e ae 7f 2e 92 f7 a7 27 0f e5 63 c4 37 5f 78 5c"
    " 59 94 b2 10"
)
_PRE64_BOOT_21_A = bytes.fromhex("e4309167ec2d221d1c260667420f5d0d5b84ff4219")
_PRE64_BOOT_21_B = bytes.fromhex("13183d38a84ad44651a9d23592a33026b00160cbb1")
_PRE64_BOOT_579 = bytes.fromhex(
    "7bf0d4d314aa32c087d09901e07def7c0a95dc2de63477d21bb6301e7231caa3428419a45a897d08fc712207fc122d0bdd7e16cce10309883f4d72e05aa3a374cb35b59101e05f85a6ff02ceba36bd3e82c57a60c6a8cb572dc1b0ec2f733d4186b9ea2a6db6a1fee2fb6e7fd4e5fc1459864f3c01ebfb921c4888a5fb98275263d7385ef849e5339522eab9600f4189646e162117491d7f33c90d491e858e186b73befd259ed2361c796337766b2e559615e6f544334f2937de1211cde7313fc052a1a16b2940ed7f9f1213b3f8a85c58b8c32a8e75970179644a39936273faac0cf721e88bc82164a588afbea7c0d400f91f514996bc510ae357ff2c95ec7e7b59220c0755e4a6697346b281c4c37dae7021278ff3e7cbbd780a045902df93c147a541edd61d43e473f8bfde1bf5740891aa0425d715ca4e65498c3e1ba30f0b11f0efbd59b2cf5f03d347f37934471e5840dea2b9c3ece5f1130f157556598d2c282e57f7c57dd98ef9170a10eb03d09c8e935a6d397958517cc567803ec2ec9cd5065993cafdef7560520630add27fe04ec151eea07bbbd3c90d5e9870ce82af07aa029d6aac4aa0069f847c02e352fe21985c6d3caf7f4617977593b4076dac3259cb0eb6136457155894ab89a59c1b778809907141dd348ddcea8532562d0a6c633aadb7e84761f4d15430aebc12818f1de17e9b370afb8cc4bba7a61abbb85b999d2a713bf66f6af13a24158e89444d1c26ba803850ed18a8c178f255f87f65cc928a857588c69ceaa2e4a269b663564bb94a6619f3157b0db319a963fcb901"
)
_20922_PRELOGIN_SEND_STATE = bytes.fromhex(
    "00000a091a4b2e8bc92f6987b74f5a89229b17dcccfb60cb5d4e941e353157e9"
    "ad36ef775225f15ccef7bf43c2136fa8e89d3ebcf039ff45a316804205027b7e"
    "6393337a418f297f2ad2f4dae39e1c54ee8c0461c4929fb3af5b81002cbd4d37"
    "474aeb918da69cdfc5ac4919beb6b99586cd486e6aabb1bbe4e2fe7cde28ca8a"
    "ae5972d10f1d3462798ee5d7c3fae6a021649632dd7d4cd3660114d874c1aaf5"
    "12b011b5445583510e0b2b8898033b53c865a5db0cc0ed752699851827561038"
    "fd2d67a9f33fa406d082e115b4d450c6cf07f67623a27097719a20d973d678a7"
    "c7e7906c5ef2fcf9401bea3a3de08458246b46b83c5f0d081f68f8b2d5ba30ec"
    "6da1"
)
_20922_PRELOGIN_RECV_STATE = bytes.fromhex(
    "0000f6911d492c37fe2e8515ddc270041422d51f300336c419dfd46b4ed08ac1"
    "3fbb124d8e3873c9a741297a876a4864aeb046b413c83ddb3c543a664fb176a1"
    "422863b75a6d6006cf4002234a5f83898f526e4717adee7e68c5ac7b6cd77ca0"
    "d818980a8b50727df3a94c92248dce7121073380e675394b9b97a316afb37f84"
    "99ab5ba27786bdc7e09cbef7252661ba9358942b79c0e39e9f34f067e2cc1a59"
    "565ef8d9653269f42a62d2dc352fb9ed45c3433e95eb01d3c6f50de82d5c10bf"
    "09fdd1113beffcb6ffaafbe90e315d55da1cca5744b87851fa96a8e7b2e4f190"
    "eceacd20b58853086f1ee1a4f974278ca59dcb9a81e50b1b05bc0cd6f2dea600"
    "820f"
)
_AUXI21_PAYLOAD = bytes.fromhex("04a3681cd09eeb67cd")
_POST_31 = bytes.fromhex(
    "1958e0c51cc776b2994d2f24f406caa58688b69760140cedccc993728b4d45dd"
    "045b15a9c11338c67407ff3180852c2d38bc568af358aa5f5a967ec6b86c431d"
    "1e7176d9b2b20ce680dcc84db7e7bf104b4af9baf8439e191f35d0ce2888e3bd"
    "61c2d5b7886a3c42dcd6ead122712d50582e9d906228"
)
_POST_31_DELAY_SEC = 0.78
_SESS_BASE = 1773180069
_CLST = 126890
_MID = "$b42e99ed2ba8"
_SERVER_SKEY = "$b54ca8de40238572024704cc4de73590"
_DEFAULT_PARAMS = "TRACK%3d4000%0aDIR%3d0%0aLAPS%3d3"
_REMOVED_GAME_TOMBSTONE_SEC = 15.0
_SHORT_FRAME_TAGS = (b"newsbadc", b"userbadc")
_ALT_FRAME_CMDS = {b"*ath", b"*pat", b"PERS", b"AUXI", b"GCRE", b"GJOI", b"GSET", b"TERM", b"*con", b"@cnt", b"@alv"}
_AUTH_IMST_RESERVED = 0x696D7374
_AUTH_LOGN_RESERVED = 0x6C6F676E
_AUTH_PASS_RESERVED = 0x70617373
_DUPL_RESERVED = 0x6475706C
_ALT_SESS = "517"
_READY_OPFLAG = 134217728
_READY_USER_FLAG = 0x2000000
_TRACE_RECV_CMDS = {
    "gcre", "GCRE", "gjoi", "GJOI", "gset", "GSET", "gsea", "glea", "gdel", "onln", "KICK", "TERM",
}
_TRACE_SEND_CMDS = {
    "gcre", "gjoi", "gset", "+usr", "+gam", "+agm", "+mgm", "+who", "+msg", "onln", "glea", "gdel", "KICK", "TERM", "+sst", "+ses",
}
_TRACE_ORDER_CMDS = {"gcre", "gjoi", "gset", "+mgm", "+ses"}
_TRACE_FIELDS = (
    "IDENT", "NAME", "HOST", "COUNT", "CUSTFLAGS", "SYSFLAGS", "USERFLAGS",
    "KICK", "PERS", "I", "M", "N", "F", "G", "GAME", "ROOM", "SYNC",
    "OPID0", "OPPO0", "OPFLAG0", "OPID1", "OPPO1", "OPFLAG1",
)
_TRACE_REDACT_FIELDS = {"X", "AUX", "TEXT", "S"}
_20921_CERT_PREFIX = bytes.fromhex(
    "833e04000100020320000300103082031c30820285a00302010202144b1b66348f3d4c270132b5353e120beb203e46f7300d06092a864886f70d01010505003081a0310b30090603550406130255533113301106035504080c0a43616c69666f726e69613115301306035504070c0c526564776f6f642043697479311e301c060355040a0c15456c656374726f6e696320417274732c20496e632e3120301e060355040b0c174f6e6c696e6520546563686e6f6c6f67792047726f75703123302106035504030c1a4f54473320436572746966696361746520417574686f72697479301e170d3233303231343231303833315a170d3333303231313231303833315a3081a0310b30090603550406130255533113301106035504080c0a43616c69666f726e69613115301306035504070c0c526564776f6f642043697479311e301c060355040a0c15456c656374726f6e696320417274732c20496e632e3120301e060355040b0c174f6e6c696e6520546563686e6f6c6f67792047726f75703123302106035504030c1a4f54473320436572746966696361746520417574686f7269747930819d300d06092a864886f70d010101050003818b0030818702818100a57f9654cef57339f0e2bb79ba01c1faaee27b7361d8e87a504c5e453f7dc446fc14831d70fd873e01280df596bba6519f8f7f6b787184c8c7f863cdca67b90731587b82b251a337975da6c0c190f9e62da5981c0b2b4a76f4ab86c1ea11260248dde33a2bc49e61047a2d4bd4b95dd58926bbb4228028f2e125da977c358ad9020103a3533051301d0603551d0e04160414f337137f5c3401459a3b4160170fe9ab417fad75301f0603551d23041830168014f337137f5c3401459a3b4160170fe9ab417fad75300f0603551d130101ff040530030101ff300d06092a864886f70d0101050500038181001353cb98bfdcd704e2294066eb8af179f39b4224db3dbefdd73e3d7406556a130aa39d9d08dca648299e71e047cb10aae59ce6cfcc75f3d005a06e67286b66fbd62187c28ffbd4c8545b4a59d9ec3e48b277983281789b21a3b70852f945e39e80f649080917451284f3b0450502e009a0ecafe5517468bbca250417c96a2ca9010080210b42e60e5930d73d588847c0fa3341"
)
_20921_RSA_N = int(
    "00a252be7324af32c7ec6fd39f5dd3ea77f6fe6a7c5943f72dece7b4dc33d024d4c494576c5aefae246654f620d636e9c02371d5f1fff9b3ab88e67bedaf3a2ca9bc9ed576639e3295f333423e28f30c47566a6f6d9c050d3c49f8b9fcfccf6d03bb3188f290f3f99d337e2fccde2d6f04ac76060d2907b53e846e58564671ef6d",
    16,
)
_20921_RSA_D = int(
    "6c3729a21874cc85484a8d14e937f1a54f5446fd90d7fa1e9defcde8228ac338830d8f9d91f51ec2eee34ec08ecf468017a1394bfffbcd1d05eefd491f7c1dc56dea50a6952d31b9b0dce95a355ba10a46a6057d2c61bbd6591f55b4b0a9534f725078e54d4d56cc5d98daa496ffac8f5c22e15b6198f65bc6fb4ba1b2efa713",
    16,
)
_20921_CHALLENGE = bytes.fromhex(
    "AD 4A 9C F4 7E 30 99 66 DC 25 7E CE 71 C2 6A 6E"
)


class ClientHandler:
    _handlers = set()
    _handlers_lock = threading.Lock()
    _detected_host_ipv4 = None
    _dir_counter = 0

    def __init__(self, server: "GameServer", user: User):
        self.srv  = server
        self.user = user
        self.conn = getattr(user, "conn", None)
        self._raw_logged = False
        self._bootstrap_mode = True
        self._await_probe_opaque = False
        self._logged_probe_opaque = False
        self._probe_opaque_total = 0
        self._probe_flow = "unknown"
        self._probe_boot_sent = False
        self._logged_probe_summary = False
        self._probe_send_state = _20922_PRELOGIN_SEND_STATE
        self._probe_recv_state = _20922_PRELOGIN_RECV_STATE
        self._probe_plain_buf = bytearray()
        self._probe_client_addr = self.user.ip
        self._probe_client_port = str(self.user.port)
        self._probe_display_name = self.user.name
        self._probe_persona = self.user.pers
        self._auth_mail = ""
        self._auth_personas = []
        self._auth_identifier = ""
        self._probe_expect_post534 = False
        self._probe_post31_buf = bytearray()
        self._probe_plain_small_ack_sent = False
        self._probe_last_ref = ""
        self._probe_aux_text = ""
        self._probe_gsea_seen = 0
        self._probe_seen_sele = False
        self._probe_seen_auth = False
        self._probe_deferred_addr_frame = b""
        self._probe_deferred_skey_frame = b""
        self._secure20921_step = 0
        self._secure20921_token = b""
        self._secure20921_peer_blob = _20921_CHALLENGE
        self._secure20921_recv_state = b""
        self._secure20921_send_state = b""
        self._secure20921_send_md5_key = b""
        self._secure20921_recv_md5_key = b""
        self._secure20921_send_seq = 1
        self._secure20921_plain_buf = bytearray()
        self._disconnect_reason = "loop_exit"
        self._dir_sess = None
        self._dir_mask = None
        self._pending_invite_game_id = 0
        self._pending_invite_at = 0.0
        self._pending_invite_from = ""
        self._pending_invite_name = ""
        self._last_gset_sig = None
        self._last_gset_at = 0.0
        self._last_ready_at = 0.0
        self._detached_replacement_done = False
        self._reattached_active_game_id = 0
        with ClientHandler._handlers_lock:
            ClientHandler._handlers.add(self)

    @staticmethod
    def _normalize_params(params: str) -> str:
        value = (params or "").strip()
        if not value:
            return _DEFAULT_PARAMS
        if "TRACK%3d" not in value and "TRACK=" not in value:
            value = "TRACK%3d4000%0a" + value
        if "DIR%3d" not in value and "DIR=" not in value:
            value += ("%0a" if value else "") + "DIR%3d0"
        if "LAPS%3d" in value:
            value = value.replace("LAPS%3d0", "LAPS%3d3")
        elif "LAPS=" in value:
            value = value.replace("LAPS=0", "LAPS=3")
        else:
            value += ("%0a" if value else "") + "LAPS%3d3"
        return value

    def _term_sst_delay(self) -> float:
        try:
            value = float(self.srv.cfg.get("LAN_TERM_SST_DELAY", 2.7) or 2.7)
        except Exception:
            value = 2.7
        return max(0.0, value)

    def _join_mgm_delay(self) -> float:
        try:
            value = float(self.srv.cfg.get("LAN_JOIN_MGM_DELAY", 0.015) or 0.015)
        except Exception:
            value = 0.015
        return max(0.0, value)

    def _join_countdown_enabled(self) -> bool:
        try:
            value = int(self.srv.cfg.get("LAN_JOIN_COUNTDOWN_ENABLE", 0) or 0)
        except Exception:
            value = 0
        return value != 0

    def _join_countdown_delay(self) -> float:
        try:
            value = float(self.srv.cfg.get("LAN_JOIN_COUNTDOWN_DELAY", 10.7) or 10.7)
        except Exception:
            value = 10.7
        return max(0.0, value)

    def _ready_countdown_enabled(self) -> bool:
        try:
            value = int(self.srv.cfg.get("LAN_READY_COUNTDOWN_ENABLE", 0) or 0)
        except Exception:
            value = 0
        return value != 0

    def _ready_notify_peers_enabled(self) -> bool:
        try:
            value = int(self.srv.cfg.get("LAN_READY_NOTIFY_PEERS", 0) or 0)
        except Exception:
            value = 0
        return value != 0

    def _gset_dedupe_window(self) -> float:
        try:
            value = float(self.srv.cfg.get("LAN_GSET_DEDUPE_WINDOW", 0.20) or 0.20)
        except Exception:
            value = 0.20
        return max(0.0, min(2.0, value))

    def _ready_unset_grace(self) -> float:
        try:
            value = float(self.srv.cfg.get("LAN_READY_UNSET_GRACE", 4.0) or 4.0)
        except Exception:
            value = 4.0
        return max(0.0, min(30.0, value))

    def _is_duplicate_gset(self, game, *, name: str, userflags_present: bool, userflags: int) -> bool:
        if game is None or not userflags_present:
            return False
        now = time.time()
        sig = (
            int(getattr(game, "id", 0) or 0),
            str(name or getattr(game, "custom", "") or "").strip().lower(),
            int(userflags),
        )
        last_sig = self._last_gset_sig
        last_at = float(self._last_gset_at or 0.0)
        self._last_gset_sig = sig
        self._last_gset_at = now
        return bool(last_sig == sig and (now - last_at) <= self._gset_dedupe_window())

    def _ready_countdown_delay(self) -> float:
        try:
            value = float(self.srv.cfg.get("LAN_READY_COUNTDOWN_DELAY", 3.0) or 3.0)
        except Exception:
            value = 3.0
        return max(0.0, value)

    @staticmethod
    def _make_plain_frame(cmd4: str, payload: bytes) -> bytes:
        raw = cmd4.encode("latin1", errors="ignore")
        if len(raw) != 4:
            raise ValueError(f"invalid LAN bootstrap cmd: {cmd4!r}")
        return raw + b"\x00\x00\x00\x00" + struct.pack(">I", 12 + len(payload)) + payload

    def _dir_fields(self, port_override: int | None = None) -> tuple[str, int, str, str]:
        host = self.srv.lobby_tcp_host(self.user.conn)
        local_host_ipv4 = self._detect_host_ipv4()
        if not self.srv.has_explicit_lobby_public_host() and (
            self.user.ip.startswith("127.")
            or (local_host_ipv4 and self.user.ip == local_host_ipv4)
        ):
            host = "127.0.0.1"
        if port_override is None:
            port = self.srv.lobby_tcp_port()
        else:
            port = int(port_override)
        if self._dir_sess is None or self._dir_mask is None:
            try:
                fixed_sess = int(self.srv.cfg.get("LAN_DIR_SESS", 0) or 0)
            except (TypeError, ValueError):
                fixed_sess = 0
            if fixed_sess > 0:
                sess = fixed_sess
            else:
                with ClientHandler._handlers_lock:
                    sess = _SESS_BASE + ClientHandler._dir_counter
                    ClientHandler._dir_counter += 1
            fixed_mask = str(self.srv.cfg.get("LAN_DIR_MASK", "") or "").strip()
            self._dir_sess = str(sess)
            self._dir_mask = fixed_mask or md5(f"{sess}:lan-dir-mask".encode("ascii", errors="ignore")).hexdigest()
        return host, port, self._dir_sess, self._dir_mask

    def _advertised_relay_fields(self, user: User | None = None):
        fields = []
        host, port = self._game_endpoint_for_user(user)
        host = str(host or "").strip()
        if host:
            fields.append(f"RELAYHOST={host}")
        if int(port or 0) > 0:
            fields.append(f"RELAYPORT={int(port)}")
        tcp_port = int(self.srv.advertised_game_tcp_port() or 0)
        if tcp_port > 0:
            fields.append(f"RELAYTCP={tcp_port}")
        return fields

    def _lite_bootstrap_fields(self) -> list[str]:
        fields: list[str] = []
        lobby_host = self.srv.lobby_tcp_host(self.user.conn)
        lobby_port = int(self.srv.lobby_tcp_port() or 0)
        control_host = self.srv.control_host(self.user.conn)
        control_port = int(self.srv.control_port() or 0)
        control_alias_host = self.srv.control_alias_host(self.user.conn)
        control_alias_port = int(self.srv.control_alias_port() or 0)
        udp_host, udp_port = self._game_endpoint_for_user(self.user)
        udp_host = str(udp_host or "").strip()
        udp_port = int(udp_port or 0)
        if lobby_host:
            fields.append(f"LOBBYHOST={lobby_host}")
        if lobby_port > 0:
            fields.append(f"LOBBYTCP={lobby_port}")
        if control_host:
            fields.append(f"CONTROLHOST={control_host}")
        if control_port > 0:
            fields.append(f"CONTROLPORT={control_port}")
        if control_alias_host:
            fields.append(f"CONTROLALIASHOST={control_alias_host}")
        if control_alias_port > 0:
            fields.append(f"CONTROLALIASPORT={control_alias_port}")
        if udp_host:
            fields.extend([f"UDPHOST={udp_host}", f"RLYHOST={udp_host}"])
        if udp_port > 0:
            fields.extend([f"UDPPORT={udp_port}", f"RLYPORT={udp_port}"])
        return fields

    def _make_dir_reply(self) -> bytes:
        host, port, sess, mask = self._dir_fields()
        self.srv.remember_dir_challenge(self.user.ip, sess, mask)
        fields = [
            f"ADDR={host}",
            f"PORT={port}",
            f"SESS={sess}",
            f"MASK={mask}",
        ] + self._lite_bootstrap_fields() + self._advertised_relay_fields(self.user)
        log.info(
            f"[uid={self.user.uid}] LAN bootstrap @dir reply addr={host} port={port} sess={sess}"
        )
        payload = "\t".join(fields).encode("ascii") + b"\x00"
        return self._make_plain_frame("@dir", payload)

    @staticmethod
    def _ksa_20921(key: bytes, rounds: int = 1) -> bytes:
        st = bytearray(258)
        st[0] = 0
        st[1] = 0
        for i in range(256):
            st[2 + i] = i
        if key and rounds > 0:
            u = 0
            for _ in range(rounds):
                p = 2
                while p - 2 < 256:
                    c = st[p]
                    b = (u + key[(p - 2) % len(key)] + c) & 0xFF
                    st[p] = st[2 + b]
                    st[2 + b] = c

                    c = st[p + 1]
                    b = (b + key[(p - 1) % len(key)] + c) & 0xFF
                    st[p + 1] = st[2 + b]
                    st[2 + b] = c

                    c = st[p + 2]
                    b = (b + key[p % len(key)] + c) & 0xFF
                    st[p + 2] = st[2 + b]
                    st[2 + b] = c

                    c = st[p + 3]
                    u = (b + key[(p + 1) % len(key)] + c) & 0xFF
                    st[p + 3] = st[2 + u]
                    st[2 + u] = c
                    p += 4
        return bytes(st)

    @staticmethod
    def _make_20921_secure_frame(send_md5: bytes, send_state: bytes, seq: int, body: bytes) -> tuple[bytes, bytes]:
        mac = md5(send_md5 + body + struct.pack(">I", seq)).digest()
        next_state, crypt = ClientHandler._rc4_apply_20921(send_state, mac + body)
        frame = struct.pack("!H", 0x8000 | len(crypt)) + crypt
        return next_state, frame

    @staticmethod
    def _decrypt_20921_secure_frame(recv_state: bytes, frame: bytes) -> tuple[bytes, bytes]:
        next_state, plain = ClientHandler._rc4_apply_20921(recv_state, frame[2:])
        return next_state, plain[16:]

    @staticmethod
    def _rsa_pkcs1_unpad_20921(block: bytes) -> bytes | None:
        if len(block) < 11 or not block.startswith(b"\x00\x02"):
            return None
        sep = block.find(b"\x00", 2)
        if sep < 10 or sep + 1 >= len(block):
            return None
        return block[sep + 1 :]

    def _make_20921_dir_reply(self) -> bytes:
        host, port, sess, mask = self._dir_fields()
        self.srv.remember_dir_challenge(self.user.ip, sess, mask)
        lines = [
            f"PORT={port}",
            f"SESS={sess}",
            f"ADDR={host}",
            f"MASK={mask}",
        ] + self._lite_bootstrap_fields() + self._advertised_relay_fields(self.user)
        payload = ("\n".join(lines) + "\n").encode("ascii") + b"\x00"
        if len(payload) < 84:
            payload += b"\x00" * (84 - len(payload))
        log.info(
            "[uid=%d] LAN bootstrap secure @dir reply addr=%s port=%d sess=%s",
            self.user.uid,
            host,
            port,
            sess,
        )
        return self._make_plain_frame("@dir", payload)

    @staticmethod
    def _make_20921_cert_frame(challenge: bytes) -> bytes:
        frame = bytearray(_20921_CERT_PREFIX)
        body = frame[2:]
        der_len = struct.unpack_from(">H", body, 5)[0]
        der_off = 2 + 11
        der = bytearray(frame[der_off:der_off + der_len])

        mod_marker = b"\x02\x81\x81\x00"
        mod_pos = der.find(mod_marker)
        if mod_pos < 0:
            raise ValueError("20921 cert modulus marker not found")
        mod = _20921_RSA_N.to_bytes(128, "big")
        der[mod_pos + len(mod_marker):mod_pos + len(mod_marker) + 128] = mod
        frame[der_off:der_off + der_len] = der
        frame[-16:] = challenge
        return bytes(frame)

    @staticmethod
    def _looks_like_20921_secure_packet(buf: bytes, off: int = 0) -> bool:
        if off < 0 or off + 2 > len(buf):
            return False
        word = struct.unpack("!H", bytes(buf[off:off + 2]))[0]
        if (word & 0x8000) == 0:
            return False
        total = (word & 0x7FFF) + 2
        return 2 <= total <= 65535

    @classmethod
    def _parse_20921_packet(cls, buf: bytes):
        if len(buf) < 2:
            return None
        if cls._looks_like_20921_secure_packet(buf, 0):
            total = (struct.unpack("!H", buf[:2])[0] & 0x7FFF) + 2
            if len(buf) < total:
                return None
            return buf[:total], total
        if len(buf) < 12:
            return None
        if not cls._is_printable_cmd4(buf[:4]) or buf[4:8] != b"\x00\x00\x00\x00":
            return None
        total = struct.unpack(">I", buf[8:12])[0]
        if total < 12 or total > 65535 or len(buf) < total:
            return None
        return buf[:total], total

    def _consume_secure_bootstrap(self, buf: bytes) -> int:
        consumed = 0
        while True:
            parsed = self._parse_20921_packet(buf[consumed:])
            if parsed is None:
                break
            frame, total = parsed
            if self._secure20921_step >= 5 and (frame[0] & 0x80) == 0:
                break

            if self._secure20921_step == 0:
                if len(frame) != 30 or (frame[0] & 0x80) == 0:
                    break
                self._secure20921_token = frame[-16:]
                self._secure20921_peer_blob = _20921_CHALLENGE
                self.user.send_bytes(self._make_20921_cert_frame(self._secure20921_peer_blob))
                self._secure20921_step = 1
                log.info(
                    "[uid=%d] LAN bootstrap secure hello len=%d token=%s",
                    self.user.uid,
                    len(frame),
                    self._secure20921_token.hex(),
                )
                consumed += total
                continue

            if self._secure20921_step == 1:
                if len(frame) != 140:
                    log.warning("[uid=%d] LAN bootstrap secure rsa mismatch len=%d", self.user.uid, len(frame))
                    break
                cipher = int.from_bytes(frame[-128:], "big")
                plain_block = pow(cipher, _20921_RSA_D, _20921_RSA_N).to_bytes(128, "big")
                unpadded = self._rsa_pkcs1_unpad_20921(plain_block)
                if unpadded is None or len(unpadded) < 16:
                    log.warning("[uid=%d] LAN bootstrap secure rsa unpad failed", self.user.uid)
                    break
                work = unpadded[-16:]
                self._secure20921_recv_md5_key = md5(
                    work + b"1" + self._secure20921_token + self._secure20921_peer_blob
                ).digest()
                self._secure20921_send_md5_key = md5(
                    work + b"0" + self._secure20921_token + self._secure20921_peer_blob
                ).digest()
                self._secure20921_recv_state = self._ksa_20921(self._secure20921_recv_md5_key, 1)
                self._secure20921_send_state = self._ksa_20921(self._secure20921_send_md5_key, 1)
                self._secure20921_send_state, out = self._make_20921_secure_frame(
                    self._secure20921_send_md5_key,
                    self._secure20921_send_state,
                    self._secure20921_send_seq,
                    b"Q",
                )
                self._secure20921_send_seq += 1
                self.user.send_bytes(out)
                self._secure20921_step = 2
                log.info("[uid=%d] LAN bootstrap secure rsa ok sent=Q", self.user.uid)
                consumed += total
                continue

            if self._secure20921_step == 2:
                if len(frame) != 35 or (frame[0] & 0x80) == 0:
                    log.warning("[uid=%d] LAN bootstrap secure step35 mismatch len=%d", self.user.uid, len(frame))
                    break
                self._secure20921_recv_state, body = self._decrypt_20921_secure_frame(
                    self._secure20921_recv_state,
                    frame,
                )
                if len(body) >= 17 and body[0] == 0x03 and body[1:17] != self._secure20921_peer_blob:
                    log.info("[uid=%d] LAN bootstrap secure peer echo differs", self.user.uid)
                self._secure20921_send_state, out = self._make_20921_secure_frame(
                    self._secure20921_send_md5_key,
                    self._secure20921_send_state,
                    self._secure20921_send_seq,
                    b"7",
                )
                self._secure20921_send_seq += 1
                self.user.send_bytes(out)
                self._secure20921_step = 3
                self._secure20921_plain_buf.clear()
                log.info("[uid=%d] LAN bootstrap secure step35 ok sent=7", self.user.uid)
                consumed += total
                continue

            if (frame[0] & 0x80) and self._secure20921_recv_state and self._secure20921_step >= 3:
                try:
                    self._secure20921_recv_state, plain = self._decrypt_20921_secure_frame(
                        self._secure20921_recv_state,
                        frame,
                    )
                    self._secure20921_plain_buf.extend(plain)
                    decoded = self._consume_bootstrap_frames(bytes(self._secure20921_plain_buf))
                    if decoded:
                        del self._secure20921_plain_buf[:decoded]
                    elif plain:
                        log.info(
                            "[uid=%d] LAN bootstrap secure plain undecoded len=%d head=%s",
                            self.user.uid,
                            len(plain),
                            plain[:48].hex(),
                        )
                    if len(self._secure20921_plain_buf) > 131072:
                        del self._secure20921_plain_buf[:-32768]
                    if self._secure20921_step == 3:
                        self._secure20921_step = 5
                        log.info("[uid=%d] LAN bootstrap secure handshake complete", self.user.uid)
                    consumed += total
                    continue
                except Exception:
                    break
            break

        return consumed

    def _make_probe_tic_reply(self) -> bytes:
        try:
            peer_ip_u32 = struct.unpack("!I", socket.inet_aton(self.user.ip))[0]
        except Exception:
            peer_ip_u32 = 0x7F000001
        text = f"{peer_ip_u32}-{self.user.port}-random-{_MID}-{_CLST}"
        payload = text.encode("ascii", errors="ignore") + b"\x00"
        if len(payload) < 72:
            payload += b"\x00" * (72 - len(payload))
        else:
            payload = payload[:72]
            if payload[-1] != 0:
                payload = payload[:-1] + b"\x00"
        return self._make_plain_frame("@tic", payload)

    @classmethod
    def _make_20922_message(cls, cmd4: str, lines) -> bytes:
        raw = cmd4.encode("latin1", errors="ignore")
        if not cls._is_printable_cmd4(raw):
            raise ValueError(f"invalid 20922 cmd: {cmd4!r}")
        if lines:
            body = ("\n".join(lines) + "\n").encode("utf-8") + b"\x00"
        else:
            body = b"\x00"
        total_len = 12 + len(body)
        return raw + b"\x00\x00\x00\x00" + struct.pack(">I", total_len) + body

    @classmethod
    def _make_20922_tab_message(cls, cmd4: str, fields) -> bytes:
        raw = cmd4.encode("latin1", errors="ignore")
        if not cls._is_printable_cmd4(raw):
            raise ValueError(f"invalid 20922 cmd: {cmd4!r}")
        if fields:
            body = "\t".join(fields).encode("utf-8") + b"\x00"
        else:
            body = b"\x00"
        total_len = 12 + len(body)
        return raw + b"\x00\x00\x00\x00" + struct.pack(">I", total_len) + body

    @classmethod
    def _make_20922_tab_message_with_tail(cls, cmd4: str, fields, tail: bytes) -> bytes:
        raw = cmd4.encode("latin1", errors="ignore")
        if not cls._is_printable_cmd4(raw):
            raise ValueError(f"invalid 20922 cmd: {cmd4!r}")
        if fields:
            body = "\t".join(fields).encode("utf-8") + b"\x00"
        else:
            body = b"\x00"
        tail = bytes(tail or b"")
        total_len = 12 + len(body) + len(tail)
        return raw + b"\x00\x00\x00\x00" + struct.pack(">I", total_len) + body + tail

    @staticmethod
    def _make_token_tab_reply(token_be32: int, fields) -> bytes:
        if fields:
            body = "\t".join(fields).encode("utf-8") + b"\x00"
        else:
            body = b"\x00"
        total_len = 12 + len(body)
        return (
            struct.pack(">I", token_be32 & 0xFFFFFFFF)
            + b"\x00\x00\x00\x00"
            + struct.pack(">I", total_len)
            + body
        )

    @staticmethod
    def _make_short_frame(tag8: str) -> bytes:
        raw = tag8.encode("latin1", errors="ignore")
        if len(raw) != 8:
            raise ValueError(f"invalid short LAN frame tag: {tag8!r}")
        return raw + struct.pack(">I", 12)

    @staticmethod
    def _format_probe_ref(ts: float | None = None) -> str:
        tm = time.localtime(time.time() if ts is None else ts)
        return (
            f"{tm.tm_year}.{tm.tm_mon}.{tm.tm_mday} "
            f"{tm.tm_hour:02d}:{tm.tm_min:02d}:{tm.tm_sec:02d}"
        )

    @classmethod
    def _make_20922_binary_message(
        cls, cmd4: str, payload: bytes, reserved_be32: int = 0
    ) -> bytes:
        raw = cmd4.encode("latin1", errors="ignore")
        if not cls._is_printable_cmd4(raw):
            raise ValueError(f"invalid 20922 cmd: {cmd4!r}")
        total_len = 12 + len(payload)
        return raw + struct.pack(">I", reserved_be32 & 0xFFFFFFFF) + struct.pack(">I", total_len) + payload

    @classmethod
    def _make_20922_wrapped_message(
        cls,
        outer_cmd4: str,
        inner_cmd4: str,
        inner_lines,
        pad_payload_to: int = 0,
    ) -> bytes:
        payload = cls._make_20922_message(inner_cmd4, inner_lines)
        if pad_payload_to > len(payload):
            payload += b"\x00" * (pad_payload_to - len(payload))
        return cls._make_20922_binary_message(outer_cmd4, payload)

    @classmethod
    def _make_20922_signed_binary_message(
        cls,
        cmd4: str,
        payload_prefix: bytes,
        total_payload_len: int,
        reserved_be32: int = 0,
    ) -> bytes:
        if total_payload_len < 8:
            raise ValueError(f"invalid signed payload length: {total_payload_len}")
        body_cap = total_payload_len - 8
        if len(payload_prefix) > body_cap:
            raise ValueError(
                f"signed payload prefix too large: {len(payload_prefix)} > {body_cap}"
            )
        payload_wo_sig = payload_prefix + (b"\x00" * (body_cap - len(payload_prefix)))
        frame_wo_sig = cls._make_20922_binary_message(
            cmd4,
            payload_wo_sig + (b"\x00" * 8),
            reserved_be32=reserved_be32,
        )
        sig8 = md5(frame_wo_sig[:-8]).digest()[:8]
        return frame_wo_sig[:-8] + sig8

    @staticmethod
    def _is_printable_cmd4(buf: bytes) -> bool:
        return len(buf) == 4 and all(32 <= b <= 126 for b in buf)

    @staticmethod
    def _is_printable_cmd8(buf: bytes) -> bool:
        return len(buf) == 8 and all(32 <= b <= 126 for b in buf)

    @classmethod
    def _looks_like_20922_header(cls, buf: bytes, off: int = 0) -> bool:
        if off < 0 or off + 12 > len(buf):
            return False
        return cls._is_printable_cmd4(buf[off : off + 4]) and buf[off + 4 : off + 8] == b"\x00\x00\x00\x00"

    @classmethod
    def _looks_like_short_frame(cls, buf: bytes, off: int = 0) -> bool:
        if off < 0 or off + 12 > len(buf):
            return False
        tag = bytes(buf[off : off + 8])
        if tag not in _SHORT_FRAME_TAGS:
            return False
        return struct.unpack(">I", bytes(buf[off + 8 : off + 12]))[0] == 12

    @classmethod
    def _looks_like_alt_frame(cls, buf: bytes, off: int = 0) -> bool:
        if off < 0 or off + 12 > len(buf):
            return False
        cmd = bytes(buf[off : off + 4])
        if cmd not in _ALT_FRAME_CMDS:
            return False
        total = struct.unpack(">I", bytes(buf[off + 8 : off + 12]))[0]
        return 12 <= total <= 0x4000

    @classmethod
    def _extract_20922_messages(cls, buf: bytearray):
        out = []
        off = 0
        n = len(buf)
        while off + 12 <= n:
            if cls._looks_like_short_frame(buf, off):
                out.append(bytes(buf[off : off + 12]))
                off += 12
                continue
            if cls._looks_like_alt_frame(buf, off):
                total = struct.unpack(">I", bytes(buf[off + 8 : off + 12]))[0]
                if off + total > n:
                    break
                out.append(bytes(buf[off : off + total]))
                off += total
                continue
            if not cls._looks_like_20922_header(buf, off):
                off += 1
                continue

            declared = struct.unpack(">I", bytes(buf[off + 8 : off + 12]))[0]
            if declared <= 0:
                off += 1
                continue

            cands = []
            if declared >= 12 and declared <= 65535 and off + declared <= n:
                cands.append(declared)
            payload_mode = declared + 12
            if payload_mode >= 12 and payload_mode <= 65535 and off + payload_mode <= n:
                cands.append(payload_mode)

            if not cands:
                if (declared >= 12 and declared <= 65535 and off + declared > n) or (
                    payload_mode >= 12 and payload_mode <= 65535 and off + payload_mode > n
                ):
                    break
                off += 1
                continue

            msg_len = cands[0]
            if len(cands) > 1:
                for cand in cands:
                    end = off + cand
                    if end == n or cls._looks_like_20922_header(buf, end):
                        msg_len = cand
                        break

            out.append(bytes(buf[off : off + msg_len]))
            off += msg_len

        if off > 0:
            del buf[:off]
        if len(buf) > 131072:
            del buf[:-32768]
        return out

    @staticmethod
    def _parse_20922_kv(body: bytes):
        txt = body.decode("utf-8", errors="replace").rstrip("\x00")
        out = {}
        txt = txt.replace("\r", "").replace("\t", "\n")
        lines = [ln.strip() for ln in txt.split("\n") if ln.strip()]
        for ln in lines:
            if "=" not in ln:
                continue
            k, v = ln.split("=", 1)
            out[k.strip()] = v.strip()
        return out

    def _frame_trace_enabled(self) -> bool:
        try:
            return int(self.srv.cfg.get("LAN_FRAME_TRACE", 1) or 0) != 0
        except Exception:
            return True

    @staticmethod
    def _trace_kv_text(kv: dict) -> str:
        parts = []
        for key in _TRACE_FIELDS:
            if key not in kv:
                continue
            value = str(kv.get(key, "") or "")
            if key in _TRACE_REDACT_FIELDS:
                value = f"<{len(value)} chars>"
            elif len(value) > 96:
                value = value[:96] + "..."
            parts.append(f"{key}={value}")
        return " ".join(parts) or "-"

    @staticmethod
    def _trace_key_order(kv: dict) -> str:
        keys = list(kv.keys())
        if len(keys) > 48:
            keys = keys[:48] + ["..."]
        return ",".join(keys) or "-"

    def _trace_incoming_frame(self, cmd: str, kv: dict, *, reserved_be32: int = 0) -> None:
        if not self._frame_trace_enabled() or cmd not in _TRACE_RECV_CMDS:
            return
        game_id = int(getattr(self.user, "game", 0) or 0)
        game = self.srv.games.get(game_id) if game_id else None
        participants = ",".join(str(int(uid)) for uid in (getattr(game, "participants", []) or [])) if game is not None else "-"
        log.info(
            "[uid=%d] LAN trace recv cmd=%s token=%08x user_game=%d stat=%s host=%d parts=%s keys=%s fields=%s",
            self.user.uid,
            cmd,
            reserved_be32 & 0xFFFFFFFF,
            game_id,
            getattr(self.user, "stat", "-"),
            int(getattr(game, "host_uid", 0) or 0) if game is not None else 0,
            participants,
            ",".join(sorted(kv.keys())) or "-",
            self._trace_kv_text(kv),
        )

    def _trace_send_frames(self, label: str, data: bytes) -> None:
        if not self._frame_trace_enabled() or not data:
            return
        off = 0
        traced = 0
        while off < len(data) and traced < 8:
            parsed = self._parse_any_bootstrap_frame(data[off:])
            if parsed is None:
                break
            cmd, payload, total = parsed
            if total <= 0:
                break
            if cmd in _TRACE_SEND_CMDS:
                kv = self._parse_20922_kv(payload)
                key_order = self._trace_key_order(kv) if cmd in _TRACE_ORDER_CMDS else "-"
                log.info(
                    "[uid=%d] LAN trace send label=%s cmd=%s len=%d order=%s fields=%s",
                    self.user.uid,
                    label or "-",
                    cmd,
                    total,
                    key_order,
                    self._trace_kv_text(kv),
                )
                traced += 1
            off += total

    @staticmethod
    def _rc4_apply_20921(state258: bytes, data: bytes):
        st = bytearray(state258)
        i = st[0]
        j = st[1]
        s = st[2:]
        out = bytearray()
        for b in data:
            i = (i + 1) & 0xFF
            j = (j + s[i]) & 0xFF
            s[i], s[j] = s[j], s[i]
            k = s[(s[i] + s[j]) & 0xFF]
            out.append(b ^ k)
        return bytes([i, j]) + bytes(s), bytes(out)

    def _send_probe_echo(self, plain: bytes):
        self._probe_send_state, crypt = self._rc4_apply_20921(self._probe_send_state, plain)
        self.user.send_bytes(crypt)

    def _secure20921_ready(self) -> bool:
        return (
            self._secure20921_step >= 3
            and bool(self._secure20921_send_md5_key)
            and bool(self._secure20921_send_state)
        )

    def _send_secure20921_plain(self, plain: bytes):
        if not plain:
            return
        self._secure20921_send_state, frame = self._make_20921_secure_frame(
            self._secure20921_send_md5_key,
            self._secure20921_send_state,
            self._secure20921_send_seq,
            plain,
        )
        self._secure20921_send_seq += 1
        self.user.send_bytes(frame)

    def _send_bootstrap_bytes(self, data: bytes, *, label: str = ""):
        if self._secure20921_ready():
            self._send_secure20921_plain(data)
        else:
            self.user.send_bytes(data)
        self._trace_send_frames(label, data)

    def _advance_probe_send_state(self, count: int):
        if count <= 0:
            return
        self._probe_send_state, _ = self._rc4_apply_20921(self._probe_send_state, b"\x00" * count)

    def _send_probe_raw_encrypted(self, wire: bytes):
        self.user.send_bytes(wire)
        self._advance_probe_send_state(len(wire))

    def _send_probe_20922_message(self, cmd4: str, lines):
        self._send_probe_echo(self._make_20922_message(cmd4, lines))

    def _send_probe_20922_binary(self, cmd4: str, payload: bytes, reserved_be32: int = 0):
        self._send_probe_echo(self._make_20922_binary_message(cmd4, payload, reserved_be32=reserved_be32))

    def _send_probe_20922_signed(self, cmd4: str, payload_prefix: bytes, total_payload_len: int):
        self._send_probe_echo(
            self._make_20922_signed_binary_message(cmd4, payload_prefix, total_payload_len)
        )

    def _send_later_bytes(self, delay_s: float, data: bytes, *, label: str = "", should_send=None):
        if not data:
            return

        def _job():
            if not self.user.connected or not self.srv.is_running:
                return
            if should_send is not None:
                try:
                    if not bool(should_send()):
                        return
                except Exception:
                    return
            self._send_bootstrap_bytes(data, label=label)
            if label:
                log.info("[uid=%d] LAN bootstrap delayed send %s len=%d", self.user.uid, label, len(data))

        timer = threading.Timer(delay_s, _job)
        timer.daemon = True
        timer.start()

    def _ensure_registered_user(self):
        if self.srv.is_user_banned(self.user):
            self.user.connected = False
            self._disconnect_reason = "admin_ban"
            return False
        if self.srv.users.get(int(self.user.uid)) is not None:
            return True
        if not self.srv.users.add(self.user):
            self.user.connected = False
            self._disconnect_reason = "server_full"
            return False
        self.srv.request_master_stat_refresh()
        return True

    def _cleanup_replaced_detached_users(self):
        if bool(getattr(self, "_detached_replacement_done", False)):
            return
        current_uid = int(getattr(self.user, "uid", 0) or 0)
        current_ip = str(getattr(self.user, "ip", "") or "").strip().lower()
        current_name = str(self._probe_display_name or self.user.name or "").strip().lower()
        current_pers = str(self._probe_persona or self.user.pers or "").strip().lower()
        if not current_name and not current_pers:
            return

        exact_matches = []
        same_ip_candidates = []
        for other in self.srv.users.all_users():
            other_uid = int(getattr(other, "uid", 0) or 0)
            if other_uid == current_uid:
                continue
            if getattr(other, "connected", True):
                continue
            other_game_id = int(getattr(other, "game", 0) or 0)
            other_room_id = int(getattr(other, "room", 0) or 0)
            other_stat = str(getattr(other, "stat", "") or "")
            detached_at = float(getattr(other, "race_detached_at", 0.0) or 0.0)
            stale_membership = bool(
                other_game_id > 0
                or other_room_id > 0
                or other_stat in (STAT_ROOM, STAT_GAME)
            )
            if detached_at <= 0.0 and not stale_membership:
                continue

            other_name = str(getattr(other, "name", "") or "").strip().lower()
            other_pers = str(getattr(other, "pers", "") or "").strip().lower()
            name_match = bool(current_name) and current_name == other_name
            pers_match = bool(current_pers) and current_pers == other_pers
            ip_match = bool(current_ip) and current_ip == str(getattr(other, "ip", "") or "").strip().lower()
            if name_match or pers_match:
                exact_matches.append(other)
            elif ip_match:
                same_ip_candidates.append(other)

        # On same-machine tests both racers share the same loopback IP, so
        # IP-only replacement is ambiguous. Prefer exact persona/name matches
        # and only fall back to IP when there is a single detached candidate.
        replacements = list(exact_matches)
        if len(replacements) > 1:
            replacements = [
                max(
                    replacements,
                    key=lambda other: float(getattr(other, "race_detached_at", 0.0) or 0.0),
                )
            ]
        current_has_membership = bool(
            int(getattr(self.user, "game", 0) or 0) > 0
            or int(getattr(self.user, "room", 0) or 0) > 0
            or str(getattr(self.user, "stat", "") or "") in (STAT_ROOM, STAT_GAME)
        )
        if not replacements and not current_has_membership and len(same_ip_candidates) == 1:
            replacements = [same_ip_candidates[0]]
        elif not replacements and len(same_ip_candidates) > 1:
            log.info(
                "[uid=%d] LAN bootstrap detached user replacement skipped ambiguous_ip=%s candidates=%s",
                current_uid,
                current_ip or "-",
                ",".join(str(int(getattr(other, "uid", 0) or 0)) for other in same_ip_candidates),
            )

        removed_any = False
        reset_games = []
        for other in replacements:
            other_uid = int(getattr(other, "uid", 0) or 0)
            game = self.srv.games.get(int(getattr(other, "game", 0) or 0)) if int(getattr(other, "game", 0) or 0) else None
            if game is not None:
                game_state = str(getattr(game, "state", "") or "")
                if game_state != "ACTIVE" and not self._reattach_open_games_enabled():
                    game_id = int(getattr(game, "id", 0) or 0)
                    game_after, removed = self.srv.games.leave(game_id, other_uid)
                    other.game = 0
                    self._on_game_departure(game or game_after, departed_uid=other_uid, removed=removed)
                    log.info(
                        "[uid=%d] LAN bootstrap discarded detached open game old_uid=%d game=%d removed=%d state=%s",
                        current_uid,
                        other_uid,
                        game_id,
                        int(removed),
                        game_state or "-",
                    )
                    game = None
                if game is None:
                    pass
                else:
                    # Reattach the reconnecting socket to active race membership.
                    # Open lobby games are intentionally discarded by default;
                    # otherwise the first newly created lobby can inherit stale
                    # host/guest state and make the host UI leave the room.
                    for idx, part_uid in enumerate(list(getattr(game, "participants", []) or [])):
                        if int(part_uid) == other_uid:
                            game.participants[idx] = current_uid
                    if current_uid not in game.participants:
                        game.participants.append(current_uid)
                    was_ready = other_uid in (getattr(game, "ready_participants", set()) or set())
                    game.ready_participants.discard(other_uid)
                    if was_ready:
                        game.ready_participants.add(current_uid)
                    if int(getattr(game, "host_uid", 0) or 0) == other_uid:
                        game.host_uid = current_uid
                    self.user.game = int(game.id)
                    self.user.stat = STAT_GAME
                    self._reattached_active_game_id = int(game.id)
                    reset_games.append(game)
                    log.info(
                        "[uid=%d] LAN bootstrap reattached detached game old_uid=%d game=%d host=%d state=%s",
                        current_uid,
                        other_uid,
                        int(getattr(game, "id", 0) or 0),
                        int(getattr(game, "host_uid", 0) or 0),
                        game_state or "-",
                    )

            old_room_id = int(getattr(other, "room", 0) or 0)
            if old_room_id:
                room = self.srv.rooms.get(old_room_id)
                if room is not None:
                    room.members.discard(other_uid)
                    room.members.add(current_uid)
                    if int(getattr(room, "host_uid", 0) or 0) == other_uid:
                        room.host_uid = current_uid
                    if int(getattr(room, "assistant_uid", 0) or 0) == other_uid:
                        room.assistant_uid = current_uid
                    self.user.room = old_room_id
                    if not self.user.game:
                        self.user.stat = STAT_ROOM
                other.room = 0

            self.srv.users.remove(other_uid)
            removed_any = True
            log.info(
                "[uid=%d] LAN bootstrap replaced detached user old_uid=%d name=%s pers=%s ip=%s",
                current_uid,
                other_uid,
                getattr(other, "name", "") or "-",
                getattr(other, "pers", "") or "-",
                getattr(other, "ip", "") or "-",
            )

        if removed_any:
            self._detached_replacement_done = True
            self.srv.request_master_stat_refresh()

    def _reattach_open_games_enabled(self) -> bool:
        try:
            return int(self.srv.cfg.get("LAN_REATTACH_OPEN_GAMES", 0) or 0) != 0
        except Exception:
            return False

    def _preserve_on_peer_close(self, active_game) -> bool:
        if active_game is None:
            return False
        if not (
            self._disconnect_reason == "peer_closed"
            or str(self._disconnect_reason).startswith("recv_error:")
        ):
            return False
        try:
            enabled = int(self.srv.cfg.get("LAN_DETACH_ON_PEER_CLOSE", 1) or 0) != 0
        except Exception:
            enabled = True
        if not enabled:
            return False
        state = str(getattr(active_game, "state", "") or "")
        return state == "ACTIVE"

    def _persona_unique_enabled(self) -> bool:
        try:
            raw = self.srv.cfg.get("LAN_PERSONA_UNIQUE", 1)
            if isinstance(raw, str):
                text = raw.strip().lower()
                if text in ("0", "false", "no", "off", ""):
                    return False
                if text in ("1", "true", "yes", "on"):
                    return True
            return int(raw or 0) != 0
        except Exception:
            return True

    def _persona_conflict(self, persona: str):
        if not self._persona_unique_enabled():
            return None
        wanted = str(persona or "").strip().lower()
        if not wanted:
            return None
        current_uid = int(getattr(self.user, "uid", 0) or 0)
        for other in self.srv.users.all_users():
            other_uid = int(getattr(other, "uid", 0) or 0)
            if other_uid == current_uid:
                continue
            if not getattr(other, "connected", True):
                continue
            other_pers = str(getattr(other, "pers", "") or "").strip().lower()
            if other_pers and other_pers == wanted:
                return other
        for handler in self._snapshot_handlers():
            if handler is self:
                continue
            other = getattr(handler, "user", None)
            if other is None or not getattr(other, "connected", True):
                continue
            other_uid = int(getattr(other, "uid", 0) or 0)
            if other_uid == current_uid:
                continue
            other_pers = str(getattr(handler, "_probe_persona", "") or getattr(other, "pers", "") or "").strip().lower()
            if other_pers and other_pers == wanted:
                return other
        return None

    def _reject_persona_conflict(self, send_frame, persona: str, conflict, stage: str) -> None:
        try:
            if str(stage or "").lower() == "cper":
                send_frame(
                    self._make_20922_signed_binary_message(
                        "cper",
                        b"\x00",
                        9,
                        reserved_be32=_DUPL_RESERVED,
                    )
                )
            else:
                send_frame(self._make_short_frame("userbadc"))
        except Exception:
            pass
        conflict_uid = int(getattr(conflict, "uid", 0) or 0)
        log.warning(
            "[uid=%d] LAN persona rejected stage=%s persona=%s already_uid=%d already_name=%s",
            self.user.uid,
            stage,
            str(persona or "-")[:64],
            conflict_uid,
            str(getattr(conflict, "name", "") or "-")[:64],
        )
        if str(stage or "").lower() == "cper":
            return
        self._disconnect_reason = f"persona_in_use:{stage}"
        self.user.connected = False
        try:
            self.user.conn.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass

    def _claim_persona_or_reject(self, persona: str, send_frame, stage: str) -> bool:
        self._cleanup_replaced_detached_users()
        conflict = self._persona_conflict(persona)
        if conflict is None:
            return True
        self._reject_persona_conflict(send_frame, persona, conflict, stage)
        return False

    @classmethod
    def _snapshot_handlers(cls):
        with cls._handlers_lock:
            return list(cls._handlers)

    def _broadcast_bytes(self, data: bytes, *, include_self: bool = True, delay_s: float = 0.0, label: str = ""):
        if not data:
            return
        for handler in self._snapshot_handlers():
            if not include_self and handler is self:
                continue
            if not handler.user.connected:
                continue
            if delay_s > 0:
                handler._send_later_bytes(delay_s, data, label=label)
            else:
                handler._send_bootstrap_bytes(data)

    @staticmethod
    def _format_time(ts: float | None = None) -> str:
        tm = time.localtime(time.time() if ts is None else ts)
        # LAN captures use non-padded month/day but fixed-width HH:MM:SS.
        return f"{tm.tm_year}.{tm.tm_mon}.{tm.tm_mday} {tm.tm_hour:02d}:{tm.tm_min:02d}:{tm.tm_sec:02d}"

    def _server_addr(self) -> str:
        return self.srv.lobby_tcp_host(self.user.conn)

    def _game_endpoint_for_user(self, user: User | None):
        configured_endpoint = None
        try:
            if user is None:
                configured_endpoint = self.srv.advertised_game_endpoint_for()
            else:
                configured_endpoint = self.srv.advertised_game_endpoint_for(
                    uid=int(getattr(user, "uid", 0) or 0),
                    name=self._display_name_for(user),
                    persona=self._persona_for(user),
                )
        except Exception:
            configured_endpoint = None
        if configured_endpoint is not None:
            host, port = configured_endpoint
            if str(host or "").strip() and int(port or 0) > 0:
                return str(host).strip(), int(port)
        if user is not None:
            try:
                client_addr = str(self._client_addr_for(user) or "").strip()
            except Exception:
                client_addr = ""
            if client_addr.startswith("127."):
                host = self.srv._runtime_local_host(self.user.conn)
                port = int(getattr(self.srv, "udp_relay_port", 0) or self.srv.advertised_game_port())
                if host and int(port or 0) > 0:
                    return host, int(port)
        if hasattr(self.srv, "race_udp_endpoint_for"):
            if user is None:
                return self.srv.race_udp_endpoint_for(conn=self.user.conn)
            return self.srv.race_udp_endpoint_for(
                conn=self.user.conn,
                name=self._display_name_for(user),
                persona=self._persona_for(user),
            )
        if user is None:
            return self.srv.advertised_game_endpoint_for()
        return self.srv.advertised_game_endpoint_for(
            uid=int(getattr(user, "uid", 0) or 0),
            name=self._display_name_for(user),
            persona=self._persona_for(user),
        )

    def _game_relay_addr(self, user: User | None = None) -> str:
        if not self._include_relay_fields():
            return ""
        host, _port = self._game_endpoint_for_user(user)
        return host

    def _game_relay_port(self, fallback: int = 0, user: User | None = None) -> int:
        relay_addr = self._game_relay_addr(user)
        if relay_addr:
            _host, port = self._game_endpoint_for_user(user)
            return int(port or fallback or 0)
        return int(fallback or 0)

    def _include_relay_fields(self) -> bool:
        try:
            raw = self.srv.cfg.get("INCLUDE_RELAY_FIELDS", 0)
            value = 0 if raw is None or raw == "" else int(raw)
        except Exception:
            value = 0
        return value != 0

    def _display_name(self) -> str:
        return self._probe_display_name or self.user.name or f"Player{self.user.uid}"

    def _persona(self) -> str:
        return self._probe_persona or self.user.pers or self._display_name()

    def _record_rept(self, kv: dict, *, source: str) -> None:
        target = str(kv.get("PERS", "") or kv.get("USER", "") or kv.get("NAME", "") or "").strip()
        report_type = str(kv.get("TYPE", "") or kv.get("TEXT", "") or kv.get("REASON", "") or "").strip()
        lang = str(kv.get("LANG", "") or "").strip()
        reason = report_type or ("presence-check" if not target else "")
        if lang:
            reason = f"{reason} LANG={lang}".strip()
        self.srv.control_social_report(self._persona(), target, reason)
        log.info(
            "[uid=%d] LAN bootstrap %s cmd=rept reporter=%s target=%s type=%s lang=%s",
            self.user.uid,
            source,
            self._persona() or "-",
            target or "-",
            report_type or "-",
            lang or "-",
        )

    def _rept_ack_frame(self) -> bytes:
        return self._make_20922_tab_message("rept", ["TEXT=Report complete"])

    def _visible_games_for_user(self, user: User | None, *, include_kicked: bool = False) -> list:
        uid = int(getattr(user, "uid", 0) or 0) if user is not None else 0
        games = []
        for game in self.srv.games.list_games():
            kicked = getattr(game, "kicked_uids", set()) or set()
            if not include_kicked and uid and int(uid) in kicked:
                continue
            participants = list(getattr(game, "participants", []) or [])
            host_uid = int(getattr(game, "host_uid", 0) or 0)
            host_user = self.srv.users.get(host_uid) if host_uid else None
            connected_participants = 0
            for part_uid in participants:
                part_user = self.srv.users.get(int(part_uid))
                if part_user is not None and getattr(part_user, "connected", False):
                    connected_participants += 1
            # Do not advertise zombie games left behind by preserved race users.
            if participants and connected_participants <= 0:
                continue
            if host_uid and (host_user is None or not getattr(host_user, "connected", False)):
                continue
            games.append(game)
        return games

    def _game_count(self, user: User | None = None) -> int:
        return len(self._visible_games_for_user(user or self.user))

    def _clear_stale_game_memberships(self, *, keep_game_id: int = 0, reason: str = ""):
        uid = int(getattr(self.user, "uid", 0) or 0)
        keep_game_id = int(keep_game_id or 0)
        removed_any = False

        # Handle stale game reference: the game was destroyed externally
        # (e.g. by _cleanup_detached_race_users) without notifying this client.
        stale_game_id = int(getattr(self.user, "game", 0) or 0)
        if stale_game_id > 0 and stale_game_id != keep_game_id and self.srv.games.get(stale_game_id) is None:
            self.user.game = 0
            self.user.stat = STAT_ROOM if self.user.room else STAT_LOBBY
            self._emit_game_leave_reset(self, None, delay_s=0.01, self_leave=True)
            self.srv.request_master_stat_refresh()
            removed_any = True
            log.info(
                "[uid=%d] LAN bootstrap cleared dead game reference reason=%s game=%d (externally destroyed)",
                uid,
                reason or "-",
                stale_game_id,
            )

        for game in list(self.srv.games.list_games()):
            game_id = int(getattr(game, "id", 0) or 0)
            if game_id <= 0 or game_id == keep_game_id:
                continue
            participants = list(getattr(game, "participants", []) or [])
            if uid not in participants and int(getattr(self.user, "game", 0) or 0) != game_id:
                continue
            try:
                game_after, removed = self.srv.games.leave(game_id, uid)
            except Exception:
                game_after, removed = game, False
            self._on_game_departure(game or game_after, departed_uid=uid, removed=removed)
            removed_any = True
            log.info(
                "[uid=%d] LAN bootstrap cleared stale game membership reason=%s game=%d removed=%d",
                uid,
                reason or "-",
                game_id,
                int(removed),
            )
        if removed_any and int(getattr(self.user, "game", 0) or 0) != keep_game_id:
            self.user.game = keep_game_id if keep_game_id > 0 else 0
            self.user.stat = STAT_ROOM if self.user.room else STAT_LOBBY
            self.srv.request_master_stat_refresh()

    def _finalize_reattached_active_game_for_lobby(self, *, reason: str = ""):
        game_id = int(getattr(self, "_reattached_active_game_id", 0) or 0)
        if game_id <= 0:
            return None
        if int(getattr(self.user, "game", 0) or 0) != game_id:
            self._reattached_active_game_id = 0
            return None

        game = self.srv.games.get(game_id)
        if game is None:
            self.user.game = 0
            self.user.stat = STAT_ROOM if self.user.room else STAT_LOBBY
            self._reattached_active_game_id = 0
            self.srv.request_master_stat_refresh()
            return None
        if str(getattr(game, "state", "") or "") != "ACTIVE":
            return None

        participants = list(getattr(game, "participants", []) or [])
        host_uid = int(getattr(game, "host_uid", 0) or 0)
        if host_uid and host_uid not in participants:
            participants.insert(0, host_uid)

        try:
            self.srv.games.finish_game(game_id, {})
        except Exception:
            pass
        removed_game = self.srv.games.destroy(game_id, reason=f"postrace_lobby:{reason or 'gsea'}") or game

        for part_uid in participants:
            u = self.srv.users.get(int(part_uid))
            if u is None:
                continue
            if int(getattr(u, "game", 0) or 0) == game_id:
                u.game = 0
            if str(getattr(u, "stat", "") or "") == STAT_GAME:
                u.stat = STAT_ROOM if u.room else STAT_LOBBY

        self.user.game = 0
        self.user.stat = STAT_ROOM if self.user.room else STAT_LOBBY
        self._reattached_active_game_id = 0
        self._on_game_departure(
            removed_game,
            departed_uid=int(getattr(self.user, "uid", 0) or 0),
            removed=True,
            delay_s=0.02,
        )
        self.srv.request_master_stat_refresh()
        log.info(
            "[uid=%d] LAN bootstrap finalized reattached active game for lobby game=%d reason=%s participants=%s",
            int(getattr(self.user, "uid", 0) or 0),
            game_id,
            reason or "-",
            ",".join(str(int(uid)) for uid in participants),
        )
        return removed_game

    def _msg_fields(self, text: str, *, sender: str | None = None, attr: str = "", flag: str = ""):
        name = sender or self._persona()
        # Stock lobby chat on +msg uses compact keys. If we send TEXT/NAME
        # here, the client UI renders only the "name >" prefix and drops the
        # message body.
        fields = []
        if flag:
            fields.append(f"F={flag}")
        fields.extend([f"T={text}", f"N={name}"])
        if attr:
            fields.append(f"A={attr}")
        return fields

    @staticmethod
    def _quote_msg_text(text: str) -> str:
        value = str(text or "")
        if value.startswith('"') and value.endswith('"'):
            return value
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'

    def _handler_for_uid(self, uid: int):
        for handler in self._snapshot_handlers():
            if handler.user.uid == uid:
                return handler
        return None

    def _user_for_social_name(self, name: str):
        target = str(name or "").strip()
        if "/" in target and not target.startswith("/"):
            target = target.split("/", 1)[0].strip()
        if not target:
            return None
        direct = self.srv.users.get_by_name(target)
        if direct is not None:
            return direct
        target_norm = target.lower()
        for handler in self._snapshot_handlers():
            candidate = handler.user
            if target_norm in {
                handler._display_name_for(candidate).strip().lower(),
                handler._persona_for(candidate).strip().lower(),
                str(getattr(candidate, "name", "") or "").strip().lower(),
                str(getattr(candidate, "pers", "") or "").strip().lower(),
            }:
                return candidate
        return None

    def _deliver_invite(self, target_name: str, text: str = "") -> int:
        target_user = self._user_for_social_name(target_name)
        if target_user is None or int(target_user.uid) == int(self.user.uid):
            return 0
        target_handler = self._handler_for_uid(int(target_user.uid))
        if target_handler is None or not bool(getattr(target_handler.user, "connected", False)):
            return 0

        game = self.srv.games.get(int(getattr(self.user, "game", 0) or 0)) if getattr(self.user, "game", 0) else None
        sender_name = self._persona_for(self.user)
        game_id = int(getattr(game, "id", 0) or 0) if game is not None else 0
        game_name = str(getattr(game, "custom", "") or sender_name or "game") if game is not None else ""
        if game_id:
            kicked = getattr(game, "kicked_uids", set()) or set()
            target_uid = int(getattr(target_user, "uid", 0) or 0)
            if target_uid in kicked:
                kicked.discard(target_uid)
                log.info(
                    "[uid=%d] LAN invite cleared kicked state target_uid=%d target=%s game=%d",
                    self.user.uid,
                    target_uid,
                    target_name or "-",
                    game_id,
                )
        notice = str(text or "").strip()
        if not notice:
            notice = f"{sender_name} invited you to join {game_name or 'their game'}"

        fields = [
            f"USER={sender_name}",
            f"FROM={sender_name}",
            f"N={sender_name}",
            f"T={notice}",
            f"TEXT={notice}",
        ]
        if game_id:
            fields.extend(
                [
                    f"IDENT={game_id}",
                    f"GAME={game_id}",
                    f"GID={game_id}",
                    f"LIDENT={game_id}",
                    f"ROOM={int(getattr(game, 'room_id', 0) or 0)}",
                    f"NAME={game_name}",
                    f"LCOUNT={max(1, len(getattr(game, 'participants', []) or []))}",
                ]
            )

        if game_id:
            target_handler._pending_invite_game_id = game_id
            target_handler._pending_invite_at = time.time()
            target_handler._pending_invite_from = sender_name
            target_handler._pending_invite_name = game_name

        frames = []
        if game is not None:
            frames.extend(
                [
                    target_handler._make_20922_tab_message(
                        "+usr",
                        target_handler._usr_fields_for_user(
                            self.user,
                            sync=3,
                            game_id=game_id,
                        ),
                    ),
                    target_handler._make_20922_tab_message(
                        "+gam",
                        target_handler._gam_fields(
                            game,
                            params=target_handler._game_params(game),
                        ),
                    ),
                    target_handler._make_20922_tab_message(
                        "+mgm",
                        target_handler._game_ready_snapshot_fields(
                            game,
                            viewer_uid=int(target_user.uid),
                            tunnel_addrs=True,
                        ),
                    ),
                ]
            )
        frames.extend(
            [
                target_handler._make_20922_tab_message("InVi", fields),
                target_handler._make_20922_tab_message(
                    "+msg",
                    target_handler._msg_fields(notice, sender=sender_name, flag="I"),
                ),
            ]
        )
        target_handler._send_later_bytes(0.01, b"".join(frames), label="game-invite-target")
        log.info(
            "[uid=%d] LAN invite delivered target_uid=%d target=%s game=%d frames=%d",
            self.user.uid,
            int(target_user.uid),
            target_name or "-",
            game_id,
            len(frames),
        )
        return 1

    def _pending_invite_game(self):
        game_id = int(getattr(self, "_pending_invite_game_id", 0) or 0)
        if game_id <= 0:
            return None
        try:
            max_age = float(self.srv.cfg.get("LAN_INVITE_PENDING_SECONDS", 90) or 90)
        except Exception:
            max_age = 90.0
        invited_at = float(getattr(self, "_pending_invite_at", 0.0) or 0.0)
        if max_age >= 0 and invited_at > 0 and time.time() - invited_at > max_age:
            self._pending_invite_game_id = 0
            self._pending_invite_from = ""
            self._pending_invite_name = ""
            return None
        game = self.srv.games.get(game_id)
        if game is None or str(getattr(game, "state", "OPEN") or "OPEN") != "OPEN":
            self._pending_invite_game_id = 0
            self._pending_invite_from = ""
            self._pending_invite_name = ""
            return None
        return game

    def _display_name_for(self, user: User) -> str:
        handler = self._handler_for_uid(user.uid)
        if handler is not None and handler._probe_display_name:
            return handler._probe_display_name
        return user.name or f"Player{user.uid}"

    def _persona_for(self, user: User) -> str:
        handler = self._handler_for_uid(user.uid)
        if handler is not None and handler._probe_persona:
            return handler._probe_persona
        return user.pers or self._display_name_for(user)

    def _aux_for(self, user: User) -> str:
        handler = self._handler_for_uid(user.uid)
        if handler is not None and handler._probe_aux_text:
            return handler._probe_aux_text
        if user.aux:
            return user.aux
        game_id = int(getattr(user, "game", 0) or 0)
        if game_id:
            game = self.srv.games.get(game_id)
            if game is not None:
                # Avoid rebuilding a snapshot while _snapshot_user is already
                # asking for AUX; use the last remembered value only.
                snaps = getattr(game, "_user_snapshots", {}) or {}
                snap = snaps.get(int(user.uid))
                snap_aux = str((snap or {}).get("aux", "") or "").strip()
                if snap_aux:
                    return snap_aux
        return ""

    def _client_addr_for(self, user: User) -> str:
        handler = self._handler_for_uid(user.uid)
        if handler is not None and handler._probe_client_addr:
            raw_addr = handler._probe_client_addr
        else:
            raw_addr = user.laddr or user.ip
        addr = raw_addr or "127.0.0.1"
        if self._game_loopback_mode():
            return "127.0.0.1"
        if addr.startswith("127."):
            game_id = int(getattr(user, "game", 0) or 0)
            if game_id:
                game = self.srv.games.get(game_id)
                host_uid = int(getattr(game, "host_uid", 0) or 0) if game is not None else 0
                if game is not None and int(user.uid) != host_uid:
                    lan_addr = self._detect_host_ipv4()
                    if lan_addr:
                        return lan_addr
        return addr

    def _game_loopback_mode(self) -> bool:
        for key in ("RACE_PUBLIC_HOST", "RACE_LISTEN_HOST", "RACE_UDP_HOST", "ADVERTISED_GAME_HOST"):
            host = str(self.srv.cfg.get(key, "") or "").strip()
            if host:
                return host.startswith("127.")
        return str(self._server_addr() or "").strip().startswith("127.")

    def _loopback_alias_peers(self) -> bool:
        return bool(int(self.srv.cfg.get("LAN_LOOPBACK_ALIAS_PEERS", 0) or 0))

    @classmethod
    def _detect_host_ipv4(cls) -> str:
        cached = cls._detected_host_ipv4
        if cached is not None:
            return cached
        addr = ""
        try:
            with open("/proc/net/fib_trie", "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()
            for idx, line in enumerate(lines[:-1]):
                stripped = line.strip()
                if not stripped.startswith("|-- "):
                    continue
                candidate = stripped[4:].strip()
                try:
                    ip = ipaddress.ip_address(candidate)
                except ValueError:
                    continue
                if not isinstance(ip, ipaddress.IPv4Address):
                    continue
                if not ip.is_private or ip.is_loopback:
                    continue
                if "/32 host LOCAL" in lines[idx + 1]:
                    addr = candidate
                    break
        except Exception:
            addr = ""
        cls._detected_host_ipv4 = addr
        return addr

    @staticmethod
    def _ipv4_hex(addr: str) -> str:
        try:
            return socket.inet_aton(addr).hex()
        except OSError:
            return "7f000001"

    def _game_handlers(self, game_id: int):
        game = self.srv.games.get(int(game_id))
        game_uids: set[int] = set()
        if game is not None:
            host_uid = int(getattr(game, "host_uid", 0) or 0)
            if host_uid > 0:
                game_uids.add(host_uid)
            for uid in getattr(game, "participants", []) or []:
                uid_int = int(uid)
                if uid_int > 0:
                    game_uids.add(uid_int)
        out = []
        snapshot = self._snapshot_handlers()
        debug_rows = []
        for handler in snapshot:
            debug_rows.append(
                "uid=%d connected=%d user_game=%d in_game=%d"
                % (
                    int(handler.user.uid),
                    1 if handler.user.connected else 0,
                    int(handler.user.game or 0),
                    1 if int(handler.user.uid) in game_uids else 0,
                )
            )
            if not handler.user.connected:
                continue
            if handler.user.game == game_id or int(handler.user.uid) in game_uids:
                out.append(handler)
        log.info(
            "[uid=%d] LAN bootstrap handler lookup game=%d game_uids=%s selected=%s snapshot=%s",
            self.user.uid,
            int(game_id),
            sorted(game_uids),
            [int(handler.user.uid) for handler in out],
            debug_rows,
        )
        return out

    def _effective_game_addr(self, game, uid: int, raw_addr: str) -> str:
        addr = raw_addr or "127.0.0.1"
        server_addr = str(self._server_addr() or "").strip()
        if server_addr.startswith("127."):
            if addr.startswith("127."):
                return addr
            return "127.0.0.1"
        host_uid = int(getattr(game, "host_uid", 0) or 0) if game is not None else 0
        if addr.startswith("127.") and host_uid and int(uid) != host_uid:
            lan_addr = self._detect_host_ipv4()
            if lan_addr:
                return lan_addr
        return addr

    def _shared_private_addr(self, game) -> str:
        if game is None:
            return ""
        addrs: list[str] = []
        host_uid = int(getattr(game, "host_uid", 0) or 0)
        if host_uid:
            host_snap = self._snapshot_for_uid(game, host_uid) or self._host_snapshot(game)
            addrs.append(self._effective_game_addr(game, host_uid, str(host_snap["addr"])))
        for uid in game.participants:
            if int(uid) == host_uid:
                continue
            snap = self._snapshot_for_uid(game, uid)
            if snap is None:
                continue
            addrs.append(self._effective_game_addr(game, int(uid), str(snap["addr"])))
        if len(addrs) < 2:
            return ""
        first = addrs[0]
        try:
            ip = ipaddress.ip_address(first)
        except ValueError:
            return ""
        if not isinstance(ip, ipaddress.IPv4Address) or not ip.is_private or ip.is_loopback:
            return ""
        if all(addr == first for addr in addrs[1:]):
            return first
        return ""

    @staticmethod
    def _alias_addr(base_addr: str, used: set[str]) -> str:
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

    def _game_addr_map(self, game) -> dict[int, str]:
        mapping: dict[int, str] = {}
        used: set[str] = set()
        participants = []
        host_uid = int(getattr(game, "host_uid", 0) or 0)
        shared_private_addr = self._shared_private_addr(game)
        loopback_mode = self._game_loopback_mode()
        if host_uid:
            host_snap = self._snapshot_for_uid(game, host_uid) or self._host_snapshot(game)
            participants.append(host_snap)
        for uid in game.participants:
            if int(uid) == host_uid:
                continue
            snap = self._snapshot_for_uid(game, uid)
            if snap is not None:
                participants.append(snap)
        for snap in participants:
            uid = int(snap["uid"])
            if loopback_mode:
                base_addr = "127.0.0.1"
                if self._loopback_alias_peers():
                    addr = base_addr if base_addr not in used else self._alias_addr(base_addr, used)
                else:
                    addr = base_addr
            elif shared_private_addr:
                if loopback_mode:
                    addr = "127.0.0.1"
                else:
                    # Same-PC LAN runs are separated by forced UDP ports now,
                    # so keep both clients on the reachable LAN address. The
                    # loopback self-view can leave the host stuck before it
                    # emits the first raw race-state packets.
                    addr = shared_private_addr
            else:
                base_addr = self._effective_game_addr(game, uid, str(snap["addr"]))
                addr = base_addr
                if addr in used:
                    addr = self._alias_addr(base_addr, used)
            mapping[uid] = addr
            used.add(addr)
        return mapping

    def _game_serv_addr(self, game) -> str:
        if self._game_loopback_mode():
            return "127.0.0.1"
        if self._shared_private_addr(game):
            return "127.0.0.1"
        return self._server_addr()

    def _game_params(self, game, fallback: str = "") -> str:
        return getattr(game, "_params", fallback or _DEFAULT_PARAMS)

    def _game_custflags(self, game, fallback: str = "0") -> str:
        return getattr(game, "_custflags", fallback)

    def _game_sysflags(self, game, fallback: str = "0", *, extra_bits: int = 0) -> str:
        raw = getattr(game, "_sysflags", fallback)
        try:
            value = int(str(raw or fallback).strip() or "0")
        except Exception:
            value = 0
        if extra_bits:
            value |= int(extra_bits)
        return str(value)

    def _game_partparams_for(self, game, uid: int) -> str:
        if len(getattr(game, "participants", []) or []) <= 1:
            return ""
        store = getattr(game, "_player_partparams", {}) or {}
        value = str(store.get(int(uid), "")).strip()
        return value or self._game_params(game)

    def _game_opparam_for(self, game, uid: int) -> str:
        if len(getattr(game, "participants", []) or []) <= 1:
            return ""
        store = getattr(game, "_player_opparams", {}) or {}
        value = str(store.get(int(uid), "")).strip()
        return value or self._game_params(game)

    def _remember_game_player_params(self, game, uid: int, kv: dict, *, params: str = ""):
        if game is None:
            return
        fallback = params or self._game_params(game)
        part_value = ""
        opp_value = ""
        userpart = -1
        try:
            userpart = int(str(kv.get("USERPART", "") or "").strip() or "-1")
        except Exception:
            userpart = -1
        userparams = str(kv.get("USERPARAMS", "") or "").strip()
        if 0 <= userpart:
            part_key = f"PARTPARAMS{userpart}"
            opp_key = f"OPPARAM{userpart}"
            part_value = str(kv.get(part_key, "") or "").strip()
            opp_value = str(kv.get(opp_key, "") or "").strip()
        if userparams:
            opp_value = userparams
        for key, value in kv.items():
            if not part_value and key.startswith("PARTPARAMS") and value.strip():
                part_value = value.strip()
            if not opp_value and key.startswith("OPPARAM") and value.strip():
                opp_value = value.strip()
            if part_value and opp_value:
                break
        if not part_value:
            part_value = fallback
        if not opp_value:
            opp_value = fallback
        part_store = dict(getattr(game, "_player_partparams", {}) or {})
        opp_store = dict(getattr(game, "_player_opparams", {}) or {})
        part_store[int(uid)] = part_value
        opp_store[int(uid)] = opp_value
        setattr(game, "_player_partparams", part_store)
        setattr(game, "_player_opparams", opp_store)
        log.info(
            "[uid=%d] LAN gset params stored game=%d userpart=%d userparams=%s part=%s opp=%s keys=%s",
            int(uid),
            int(getattr(game, "id", 0) or 0),
            userpart,
            userparams or "-",
            part_value or "-",
            opp_value or "-",
            ",".join(sorted(k for k in kv.keys() if k.startswith(("USER", "PARTPARAMS", "OPPARAM")))) or "-",
        )

    @staticmethod
    def _game_ready(game, uid: int) -> bool:
        ready = getattr(game, "ready_participants", set()) or set()
        return int(uid) in ready

    def _news_burst(self) -> bytes:
        mode = str(self.srv.cfg.get("LAN_NEWS_MODE", "captured") or "captured").strip().lower()
        if mode in {"legacy", "png", "~png"}:
            probe_ref = self._format_probe_ref()
            self._probe_last_ref = probe_ref
            return b"".join(
                [
                    self._make_20922_tab_message("~png", [f"REF={probe_ref}"]),
                    self._make_20922_tab_message("skey", [f"SKEY={_SERVER_SKEY}"]),
                    self._make_short_frame("newsbadc"),
                ]
            )

        news_host = str(
            self.srv.cfg.get("LAN_NEWS_HOST", "")
            or self.srv.control_host(getattr(self.user, "conn", None))
            or self._server_addr()
            or "127.0.0.1"
        ).strip()
        try:
            buddy_port = int(self.srv.cfg.get("LAN_NEWS_BUDDY_PORT", 0) or 0)
        except (TypeError, ValueError):
            buddy_port = 0
        if buddy_port <= 0:
            try:
                buddy_port = int(self.srv.control_port())
            except Exception:
                buddy_port = 20923
        try:
            http_port = int(self.srv.cfg.get("LAN_NEWS_HTTP_PORT", 0) or 0)
        except (TypeError, ValueError):
            http_port = 0
        if http_port <= 0:
            http_port = buddy_port
        http_host = news_host
        if http_port not in (0, 80):
            http_host = f"{news_host}:{http_port}"

        news_lines = [
            f"TOSURL=http://{http_host}/tos",
            "CIRCUIT_TIER_POINTS=0,1999,4999,9999,19999,39999,59999,79999,99999,119999",
            "DRAG_TIER_POINTS=0,1999,4999,9999,19999,39999,59999,79999,99999,119999",
            "URL_TIER_POINTS=0,1999,4999,9999,19999,39999,59999,79999,99999,119999",
            f"BUDDY_SERVER={news_host}",
            f"BUDDY_PORT={buddy_port}",
            "STREET_CROSS_TIER_POINTS=0,1999,4999,9999,19999,39999,59999,79999,99999,119999",
            f"NEWSURL=http://{http_host}/news",
            "SPRINT_TIER_POINTS=0,1999,4999,9999,19999,39999,59999,79999,99999",
            "DRIFT_TIER_POINTS=0,1999,4999,9999,19999,39999,59999,79999,99999,119999",
        ]
        payload = ("\n".join(news_lines) + "\n").encode("utf-8") + b"\x00"
        return self._make_20922_signed_binary_message(
            "news",
            payload,
            567,
            reserved_be32=0x6E657737,  # "new7"
        )

    def _sele_frame(self) -> bytes:
        payload = (
            b"ROOMS=1\n"
            b"SLOTS=32\n"
            b"USERSET=1\n"
            b"MORE=1\n"
            b"MYGAME=1\n"
            b"RANKS=1\n"
            b"GAMES=2\n"
            b"ASYNC=1\n"
            b"STATS=500\n"
            b"MESGS=1\n"
            b"USERS=5\n\x00"
        )
        return self._make_20922_signed_binary_message(
            "sele",
            payload,
            102,
        )

    @staticmethod
    def _account_text(account: dict, *keys: str) -> str:
        if not account:
            return ""
        for key in keys:
            value = account.get(key)
            if value is None:
                continue
            text = str(value).strip()
            if text:
                return text
        return ""

    @staticmethod
    def _account_list(account: dict, *keys: str):
        values = []
        if not account:
            return values
        for key in keys:
            raw = account.get(key)
            if raw is None:
                continue
            if isinstance(raw, list):
                items = raw
            else:
                items = str(raw).replace(";", ",").split(",")
            for item in items:
                text = str(item or "").strip()
                if text:
                    values.append(text)
        return values

    def _apply_auth_account(self, account: dict, fallback_name: str, fallback_persona: str) -> None:
        if not account:
            return
        personas = self._account_list(account, "personas", "persona", "pers")
        display = (
            self._account_text(account, "display_name", "display", "name", "username", "user")
            or fallback_name
            or self.user.name
        )
        persona = personas[0] if personas else (fallback_persona or display)
        mail = self._account_text(account, "email", "mail", "__key")

        self._auth_mail = mail
        self._auth_personas = personas
        self._auth_identifier = mail or self._account_text(account, "__key", "email", "mail", "name", "username", "user") or display or fallback_name
        self._probe_display_name = display
        self.user.name = display
        self._probe_persona = persona
        self.user.pers = persona

    @staticmethod
    def _auth_reject_reason_text(reason: str) -> str:
        return {
            "missing_identifier": "Account name is missing.",
            "missing_password": "Password is missing.",
            "no_accounts": "No LAN auth accounts are configured.",
            "unknown_account": "Account is not recognized.",
            "bad_password": "Password is incorrect.",
            "rate_limited": "Too many failed login attempts.",
            "account_in_use": "Account is already logged in.",
            "account_exists": "Account already exists.",
            "create_disabled": "Account creation is disabled.",
            "save_failed": "Account could not be saved.",
        }.get(str(reason or "").strip(), "Authentication failed.")

    def _auth_reject_frame(self, *, reserved_be32: int = _AUTH_IMST_RESERVED) -> bytes:
        return self._make_20922_signed_binary_message(
            "auth",
            b"\x00",
            9,
            reserved_be32=reserved_be32,
        )

    @staticmethod
    def _auth_reject_reserved(reason: str) -> int:
        if str(reason or "").strip() in ("bad_password", "missing_password"):
            return _AUTH_PASS_RESERVED
        return _AUTH_IMST_RESERVED

    @staticmethod
    def _account_create_reject_reserved(reason: str) -> int:
        reason = str(reason or "").strip()
        if reason == "missing_password":
            return _AUTH_PASS_RESERVED
        if reason == "account_exists":
            return _DUPL_RESERVED
        return _AUTH_IMST_RESERVED

    def _account_create_frame(self, reason: str = "created", *, ok: bool = True) -> bytes:
        reserved_be32 = 0 if ok else self._account_create_reject_reserved(reason)
        return self._make_20922_signed_binary_message(
            "acct",
            b"\x00",
            9,
            reserved_be32=reserved_be32,
        )

    def _account_conflict(self, account_name: str):
        wanted = str(account_name or "").strip().lower()
        if not wanted:
            return None
        current_uid = int(getattr(self.user, "uid", 0) or 0)
        for other in self.srv.users.all_users():
            other_uid = int(getattr(other, "uid", 0) or 0)
            if other_uid == current_uid or not getattr(other, "connected", True):
                continue
            other_name = str(getattr(other, "name", "") or "").strip().lower()
            if other_name and other_name == wanted:
                return other
        for handler in self._snapshot_handlers():
            if handler is self:
                continue
            other = getattr(handler, "user", None)
            if other is None or not getattr(other, "connected", True):
                continue
            other_uid = int(getattr(other, "uid", 0) or 0)
            if other_uid == current_uid:
                continue
            other_name = str(
                getattr(handler, "_probe_display_name", "") or getattr(other, "name", "") or ""
            ).strip().lower()
            if other_name and other_name == wanted:
                return other
        return None

    def _auth_reject_repeat(self) -> int:
        try:
            repeat = int(self.srv.cfg.get("LAN_AUTH_REJECT_REPEAT", 4) or 4)
        except (TypeError, ValueError):
            repeat = 4
        return max(1, min(8, repeat))

    def _auth_reject_interval(self) -> float:
        try:
            interval = float(self.srv.cfg.get("LAN_AUTH_REJECT_INTERVAL", 0.25) or 0.25)
        except (TypeError, ValueError):
            interval = 0.25
        return max(0.0, min(2.0, interval))

    def _auth_reject_close_delay(self, repeat: int, interval: float) -> float:
        try:
            delay = float(self.srv.cfg.get("LAN_AUTH_REJECT_CLOSE_DELAY", 1.10) or 1.10)
        except (TypeError, ValueError):
            delay = 1.10
        minimum = (max(1, int(repeat)) - 1) * max(0.0, float(interval)) + 0.20
        return max(minimum, min(10.0, delay))

    def _close_after_auth_reject(self, delay: float) -> None:
        def _job():
            self.user.connected = False
            try:
                self.user.conn.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass

        timer = threading.Timer(max(0.0, delay), _job)
        timer.daemon = True
        timer.start()

    def _send_auth_reject_later(self, send_frame, frame: bytes, delay: float, label: str) -> None:
        def _job():
            if not self.user.connected or not self.srv.is_running:
                return
            try:
                send_frame(frame)
                log.info("[uid=%d] LAN bootstrap delayed send %s len=%d", self.user.uid, label, len(frame))
            except Exception:
                pass

        timer = threading.Timer(max(0.0, delay), _job)
        timer.daemon = True
        timer.start()

    def _reject_auth(
        self,
        send_frame,
        reason: str,
        identifier: str,
        *,
        reserved_be32: int = _AUTH_IMST_RESERVED,
    ) -> None:
        frame = self._auth_reject_frame(reserved_be32=reserved_be32)
        repeat = self._auth_reject_repeat()
        interval = self._auth_reject_interval()
        try:
            send_frame(frame)
        except Exception:
            pass
        for idx in range(1, repeat):
            self._send_auth_reject_later(send_frame, frame, interval * idx, f"auth-reject-{idx + 1}")
        safe_identifier = (identifier or "-").replace("\n", " ").replace("\r", " ")
        log.warning(
            "[uid=%d] LAN auth rejected reason=%s id=%s text=%s",
            self.user.uid,
            reason,
            safe_identifier[:96],
            self._auth_reject_reason_text(reason),
        )
        self._disconnect_reason = f"auth_failed:{reason}"
        self._close_after_auth_reject(self._auth_reject_close_delay(repeat, interval))

    def _accept_auth(self, kv: dict, fallback_name: str, fallback_persona: str, send_frame) -> bool:
        auth_kv = dict(kv or {})
        sess, mask = self.srv.recent_dir_challenge(self.user.ip)
        if not sess or not mask:
            _, _, sess, mask = self._dir_fields()
        auth_kv.setdefault("SESS", sess)
        auth_kv.setdefault("MASK", mask)
        auth_kv["CHALLENGE"] = mask
        ok, reason, account, identifier = self.srv.authenticate_login(auth_kv)
        if ok:
            if account:
                self._apply_auth_account(account, fallback_name, fallback_persona)
            account_name = self._probe_display_name or self.user.name or fallback_name
            conflict = self._account_conflict(account_name)
            if conflict is not None:
                self._reject_auth(
                    send_frame,
                    "account_in_use",
                    account_name,
                    reserved_be32=_AUTH_LOGN_RESERVED,
                )
                log.warning(
                    "[uid=%d] LAN auth rejected account in use account=%s already_uid=%d",
                    self.user.uid,
                    str(account_name or "-")[:64],
                    int(getattr(conflict, "uid", 0) or 0),
                )
                return False
            if not self._claim_persona_or_reject(
                self._probe_persona or self.user.pers or fallback_persona,
                send_frame,
                "auth",
            ):
                return False
            return True
        self._reject_auth(
            send_frame,
            reason,
            identifier,
            reserved_be32=self._auth_reject_reserved(reason),
        )
        return False

    def _auth_frame(self) -> bytes:
        name = (self._probe_display_name or self.user.name or f"Player{self.user.uid}").strip()
        persona = (self._probe_persona or self.user.pers or name).strip()
        # The captured auth frame has only 122 bytes before the MD5 trailer.
        # Keep the auto-push experiment on the known-fitting capture identity.
        if self._auth_autopush_enabled():
            name = "Moio9"
            persona = "Moio"
        self._probe_display_name = name
        self.user.name = name
        self._probe_persona = persona
        tos_value = self._tos_value("LAN_AUTH_TOS", 3)
        preferred_mail = (self._auth_mail or "moio.yoyo@yahoo.com").strip()
        fallback_mail = preferred_mail if self._auth_mail else "yo@yahoo.com"

        def build(mail: str, pers: str, display: str) -> bytes:
            return (
                "\n".join(
                    [
                        f"MAIL={mail}",
                        "LAST=2005.12.8 15:51:38",
                        "BORN=20030520",
                        f"PERSONAS={self._auth_personas_value(pers)}",
                        f"TOS={tos_value}",
                        f"NAME={display}",
                        "SPAM=N",
                        "ADDR=127.0.0.1",
                    ]
                )
                + "\n"
            ).encode("utf-8") + b"\x00"

        body_cap = 122
        payload = build(preferred_mail, persona, name)
        if len(payload) > body_cap and not self._auth_mail:
            payload = build(fallback_mail, persona, name)
        if len(payload) > body_cap:
            persona = persona[: max(1, len(persona) - (len(payload) - body_cap))]
            name = name[: max(1, len(name) - max(0, len(payload) - body_cap))]
            self._probe_display_name = name
            self.user.name = name
            self._probe_persona = persona
            payload = build(fallback_mail, persona, name)
        if len(payload) > body_cap:
            overflow = len(payload) - body_cap
            mail = fallback_mail[: max(1, len(fallback_mail) - overflow)]
            persona = persona[: max(1, len(persona) - max(0, overflow - len(fallback_mail) + 1))]
            name = name[: max(1, len(name) - max(0, overflow - len(fallback_mail) + 1 - len(persona)))]
            payload = build(mail, persona, name)
        if len(payload) > body_cap:
            payload = payload[:body_cap - 1] + b"\x00"
        return self._make_20922_signed_binary_message(
            "auth",
            payload,
            130,
        )

    def _pers_frame(self, persona: str, display_name: str, cmd_name: str = "pers") -> bytes:
        def build(pers: str, name: str, final_newline: bool = True) -> bytes:
            text = "\n".join(
                [
                    "LKEY=71b83532bb417f823b16f4c457b32bc",
                    f"PERS={pers}",
                    "LAST=2006.12.8 15:51:58",
                    "PLAST=2006.12.8 16:51:40",
                    f"NAME={name}",
                ]
            )
            if final_newline:
                text += "\n"
            return text.encode("utf-8") + b"\x00"

        body_cap = 108
        payload = build(persona, display_name)
        if len(payload) > body_cap:
            payload = build(persona, display_name, final_newline=False)
        if len(payload) > body_cap:
            overflow = len(payload) - body_cap
            display_name = display_name[: max(1, len(display_name) - overflow)]
            payload = build(persona, display_name, final_newline=False)
        if len(payload) > body_cap:
            overflow = len(payload) - body_cap
            persona = persona[: max(1, len(persona) - overflow)]
            payload = build(persona, display_name, final_newline=False)
        self._probe_persona = persona
        self.user.pers = persona
        self._probe_display_name = display_name
        self.user.name = display_name
        cmd_name = "cper" if str(cmd_name or "").lower() == "cper" else "pers"
        return self._make_20922_signed_binary_message(cmd_name, payload, 116)

    def _user_frame(self) -> bytes:
        payload = (
            "LMSTAT=\n"
            "STAT=0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,\n"
            "LGAME=\n"
        ).encode("utf-8") + b"\x00"
        return self._make_20922_signed_binary_message("user", payload, 106)

    def _player_stat_csv(self, persona: str) -> str:
        try:
            return self.srv.stats.player_stat_csv(persona)
        except Exception as exc:
            log.warning("[uid=%d] LAN stats fallback persona=%r error=%s", self.user.uid, persona, exc)
            return ",".join(["270f", "0", "0", "0", "64", "65", "65"] * 5)

    def _player_stat_csv_for_user(self, user: User) -> str:
        return self._player_stat_csv(self._persona_for(user))

    def _player_rep_for_user(self, user: User) -> int:
        persona = self._persona_for(user)
        try:
            stat = self.srv.stats.get_player_stats(persona, create=True)
            return int(stat.get(0, "rep") if stat is not None else 100)
        except Exception:
            return 100

    def _cfg_int(self, key: str, default: int) -> int:
        try:
            return int(self.srv.cfg.get(key, default))
        except Exception:
            return int(default)

    def _special_persona_set(self) -> set[str]:
        raw = str(self.srv.cfg.get("LAN_SPECIAL_PERSONAS", "") or "")
        return {part.strip().lower() for part in raw.replace(";", ",").split(",") if part.strip()}

    def _is_special_user(self, user: User) -> bool:
        names = self._special_persona_set()
        if not names:
            return False
        return bool(
            self._persona_for(user).strip().lower() in names
            or self._display_name_for(user).strip().lower() in names
        )

    def _user_cl_for(self, user: User) -> int:
        if self._is_special_user(user):
            return self._cfg_int("LAN_SPECIAL_USER_CL", 511)
        return self._cfg_int("LAN_USER_CL", 0)

    def _user_rgb_for(self, user: User) -> int:
        if self._is_special_user(user):
            return self._cfg_int("LAN_SPECIAL_USER_RGB", 511)
        return self._cfg_int("LAN_USER_RGB", 0)

    def _onln_flag_for(self, user: User, *, game_active: bool) -> str:
        if self._is_special_user(user):
            return str(self.srv.cfg.get("LAN_SPECIAL_ONLN_FLAG", "G") or "G").strip()[:1] or "G"
        if game_active:
            return str(self.srv.cfg.get("LAN_ONLN_GAME_FLAG", "U") or "U").strip()[:1] or "U"
        return "U"

    def _stats_personas(self) -> list[str]:
        personas = []

        def add(value):
            text = str(value or "").strip()
            if text:
                personas.append(text)

        # Persistent stats file personas.
        try:
            for persona in self.srv.stats.player_personas():
                add(persona)
        except Exception:
            pass

        # Ranking file can contain entries even when stats.dat has no player_stats
        # yet.  Monthly/track stats requests often ask RANGE=2+; returning only
        # the current user can make the client leave the stats page blank.
        try:
            entries = getattr(self.srv.ranking, "_entries", {}) or {}
            for entry in entries.values():
                add(getattr(entry, "name", ""))
        except Exception:
            pass

        # Auth accounts/personas also provide stable names before any race result
        # has written stats.dat.
        try:
            load_accounts = getattr(self.srv, "_load_auth_accounts", None)
            if callable(load_accounts):
                for account in load_accounts():
                    for persona in account.get("personas", []) or []:
                        add(persona)
                    add(account.get("display_name", ""))
                    add(account.get("name", ""))
        except Exception:
            pass

        try:
            for user in self.srv.users.all_users():
                add(self._persona_for(user))
        except Exception:
            pass

        add(self._persona())

        out = []
        seen = set()
        for persona in personas:
            key = persona.lower()
            if key and key not in seen:
                seen.add(key)
                out.append(persona)
        return out

    @staticmethod
    def _snap_board_id(index: int, chan: int) -> int:
        # NFSOR captures use INDEX as the request slot and CHAN as the actual
        # leaderboard/stat channel. Older nfsuserver-style flows used INDEX.
        return int(chan or index or 1)

    @staticmethod
    def _track_snap_value(persona: str, board_id: int) -> int:
        digest = md5(f"{board_id}:{persona}".encode("utf-8", errors="ignore")).digest()
        if 28 <= board_id <= 35:
            return 0x20 + int.from_bytes(digest[:2], "big") % 0x400
        return 0x20 + digest[0] % 0x60

    def _track_snap_rows(self, board_id: int, start: int, limit: int, find: str = ""):
        seen = set()
        rows = []
        find_norm = str(find or "").strip().lower()
        for persona in self._stats_personas():
            persona = str(persona or "").strip()
            key = persona.lower()
            if not persona or key in seen:
                continue
            if find_norm and find_norm != "$" and find_norm not in key:
                continue
            seen.add(key)
            rows.append((self._track_snap_value(persona, board_id), persona))
        rows.sort(key=lambda item: ((-item[0]) if 28 <= board_id <= 35 else item[0], item[1].lower()))
        offset = max(0, int(start or 0))
        limit = max(1, min(100, int(limit or 100)))

        # Some monthly stat pages request RANGE=2 and remain blank if the server
        # returns only one +snp row.  Pad the generic/monthly boards with stable
        # local dummy rows so the response satisfies the requested range even
        # on a fresh server with only one real persona.
        pad_idx = 1
        existing = {name.lower() for _, name in rows}
        while len(rows) < offset + limit:
            name = f"CPU_Racer_{pad_idx}"
            pad_idx += 1
            if name.lower() in existing:
                continue
            existing.add(name.lower())
            rows.append((self._track_snap_value(name, board_id), name))
        rows.sort(key=lambda item: ((-item[0]) if 28 <= board_id <= 35 else item[0], item[1].lower()))
        return rows[offset : offset + limit]

    def _snap_burst(self, kv: dict) -> bytes:
        def as_int(name: str, default: int) -> int:
            try:
                return int(str(kv.get(name, default) or default).strip())
            except Exception:
                return default

        index = as_int("INDEX", 1)
        chan = as_int("CHAN", 0)
        start = as_int("START", 0)
        range_count = as_int("RANGE", 100)
        find = str(kv.get("FIND", "") or "").strip()
        board_id = self._snap_board_id(index, chan)
        frames = [
            self._make_20922_tab_message(
                "snap",
                [
                    f"INDEX={index}",
                    f"CHAN={chan}",
                    f"START={start}",
                    f"RANGE={range_count}",
                    "SEQN=0",
                ],
            )
        ]
        rows_count = 0
        if 1 <= board_id <= 5:
            rows = self.srv.stats.nfsu2_leaderboard(
                board_id,
                start=start,
                limit=range_count,
                include_personas=self._stats_personas(),
            )
            for rank, stat in rows:
                rows_count += 1
                frames.append(
                    self._make_20922_tab_message(
                        "+snp",
                        [
                            f"P={max(0, rank - 1):x}",
                            f"S={stat.snap_hex_csv(board_id, rank)}",
                            f"N={stat.persona}",
                            "O=1",
                        ],
                    )
                )
        else:
            for value, persona in self._track_snap_rows(board_id, start, range_count, find):
                rows_count += 1
                frames.append(
                    self._make_20922_tab_message(
                        "+snp",
                        [
                            f"P={value:x},1,1",
                            f"N={persona}",
                            "O=1",
                        ],
                    )
                )
        result = b"".join(frames)
        log.info(
            "[uid=%d] LAN stats snap index=%d chan=%d board=%d start=%d range=%d rows=%d hex=%s",
            self.user.uid,
            index,
            chan,
            board_id,
            start,
            range_count,
            rows_count,
            result.hex(),
        )
        return result

    def _auxi_frame(self) -> bytes:
        return self._make_20922_signed_binary_message("auxi", b"\x00", 9)

    def _news_autopush_enabled(self) -> bool:
        try:
            raw = self.srv.cfg.get("LAN_NEWS_AUTOPUSH_AUTH", 0)
            value = 0 if raw is None or raw == "" else int(raw)
        except Exception:
            value = 0
        return value != 0

    def _auth_autopush_enabled(self) -> bool:
        try:
            raw = self.srv.cfg.get("LAN_AUTH_AUTOPUSH", 0)
            value = 0 if raw is None or raw == "" else int(raw)
        except Exception:
            value = 0
        return value != 0

    def _tos_value(self, key: str, default: int) -> int:
        try:
            return int(self.srv.cfg.get(key, default))
        except Exception:
            return int(default)

    def _auth_personas_value(self, persona: str) -> str:
        seen = set()
        values = []
        for raw in [
            persona,
            *self._auth_personas,
            *str(self.srv.cfg.get("LAN_AUTH_EXTRA_PERSONAS", "") or "").split(","),
        ]:
            value = str(raw or "").strip()
            key = value.lower()
            if not value or key in seen:
                continue
            seen.add(key)
            values.append(value)
        return ",".join(values) if values else persona

    def _news_push_after_auth_enabled(self) -> bool:
        try:
            raw = self.srv.cfg.get("LAN_NEWS_PUSH_AFTER_AUTH", 0)
            value = 0 if raw is None or raw == "" else int(raw)
        except Exception:
            value = 0
        return value != 0

    def _news_push_delay(self) -> float:
        try:
            return max(0.0, float(self.srv.cfg.get("LAN_NEWS_PUSH_DELAY", 0.75) or 0.75))
        except Exception:
            return 0.75

    def _prelogin_burst_after_news_enabled(self) -> bool:
        mode = str(self.srv.cfg.get("LAN_NEWS_MODE", "captured") or "captured").strip().lower()
        if mode in {"legacy", "png", "~png"}:
            return False
        try:
            raw = self.srv.cfg.get("LAN_PRELOGIN_BURST_AFTER_NEWS", 1)
            value = 1 if raw is None or raw == "" else int(raw)
        except Exception:
            value = 1
        return value != 0

    def _schedule_news_auth_followups(self):
        if not self._news_autopush_enabled():
            return
        sele_frame = self._sele_frame()
        self._send_later_bytes(
            0.035,
            sele_frame,
            label="news-autosele",
            should_send=lambda: not self._probe_seen_sele,
        )
        if self._auth_autopush_enabled():
            auth_frame = self._auth_frame()
            self._send_later_bytes(
                0.12,
                auth_frame,
                label="news-autoauth",
                should_send=lambda: not self._probe_seen_auth,
            )

    def _schedule_news_push(self, label: str = "news-push"):
        frame = self._news_burst()
        self._send_later_bytes(
            self._news_push_delay(),
            frame,
            label=label,
        )

    def _who_fields_for(
        self,
        user: User,
        *,
        aux_text: str = "",
        game_active: bool = False,
        game_id: int | None = None,
    ):
        raw_client_addr = self._client_addr_for(user)
        client_addr = raw_client_addr
        loopback_mode = self._game_loopback_mode()
        if game_id is None:
            game_value = int(getattr(user, "game", 0) or 0) if game_active else 0
        else:
            game_value = int(game_id or 0)
        game = self.srv.games.get(game_value) if game_value else None
        if game is not None:
            client_addr = self._game_addr_map(game).get(int(user.uid), client_addr)
        else:
            client_addr = self._effective_game_addr(game, int(user.uid), client_addr)
        local_addr = client_addr if loopback_mode else (raw_client_addr or client_addr)
        relay_addr = self._game_relay_addr(user)
        port_value = 1 if game_value else 2
        return [
            f"I={user.uid}",
            f"M={self._display_name_for(user)}",
            f"N={self._persona_for(user)}",
            "F=U",
            f"A={client_addr}",
            f"P={port_value}",
            f"S={self._player_stat_csv_for_user(user)}",
            f"X={aux_text}",
            f"G={game_value}",
            "AT=",
            f"CL={self._user_cl_for(user)}",
            "LV=0",
            "MD=0",
            f"LA={local_addr}",
            "HW=0",
            "RP=0",
            f"MA={relay_addr}",
            "US=",
            "C=",
        ]

    def _who_fields(self, *, aux_text: str = "", game_active: bool = False, game_id: int | None = None):
        return self._who_fields_for(
            self.user,
            aux_text=aux_text,
            game_active=game_active,
            game_id=game_id,
        )

    def _room_usr_fields_for_user(self, user: User, *, game_id: int = 0):
        raw_client_addr = self._client_addr_for(user)
        client_addr = self._effective_game_addr(None, int(user.uid), raw_client_addr)
        return [
            f"I={user.uid}",
            f"N={self._persona_for(user)}",
            f"M={self._display_name_for(user)}",
            "F=H",
            f"A={client_addr}",
            "P=211",
            f"S={self._player_stat_csv_for_user(user)}",
            f"X={self._aux_for(user)}",
            f"G={int(game_id or 0)}",
            "T=2",
        ]

    def _online_who_snapshot(self, *, include_self: bool = True) -> bytes:
        frames = []
        current_uid = int(getattr(self.user, "uid", 0) or 0)
        for user in sorted(self.srv.users.all_users(), key=lambda item: int(getattr(item, "uid", 0) or 0)):
            if not getattr(user, "connected", True):
                continue
            uid = int(getattr(user, "uid", 0) or 0)
            if not include_self and uid == current_uid:
                continue
            if not str(getattr(user, "pers", "") or getattr(user, "name", "") or "").strip():
                continue
            frames.append(
                self._make_20922_tab_message(
                    "+who",
                    self._who_fields_for(
                        user,
                        aux_text=self._aux_for(user),
                        game_active=bool(getattr(user, "game", 0) or 0),
                    ),
                )
            )
        return b"".join(frames)

    def _broadcast_online_who(self, subject: User, *, delay_s: float = 0.02, exclude_uid: int | None = None) -> None:
        if not getattr(subject, "connected", True):
            return
        subject_game = int(getattr(subject, "game", 0) or 0)
        for handler in self._snapshot_handlers():
            if not handler.user.connected:
                continue
            if exclude_uid is not None and int(handler.user.uid) == int(exclude_uid):
                continue
            if subject_game <= 0 and (
                int(getattr(handler.user, "game", 0) or 0) > 0 or getattr(handler.user, "stat", "") == STAT_GAME
            ):
                log.info(
                    "[uid=%d] LAN suppress online-who subject_uid=%d subject_game=0 target_game=%s target_stat=%s",
                    int(getattr(handler.user, "uid", 0) or 0),
                    int(getattr(subject, "uid", 0) or 0),
                    getattr(handler.user, "game", 0),
                    getattr(handler.user, "stat", ""),
                )
                continue
            frame = handler._make_20922_tab_message(
                "+who",
                handler._who_fields_for(
                    subject,
                    aux_text=handler._aux_for(subject),
                    game_active=bool(getattr(subject, "game", 0) or 0),
                ),
            )
            handler._send_later_bytes(delay_s, frame, label="online-who")

    def _onln_fields_for_user(self, user: User, game, *, viewer_uid: int | None = None):
        game_id = int(getattr(game, "id", 0) or 0) if game is not None else 0
        fields = self._who_fields_for(
            user,
            aux_text=self._aux_for(user),
            game_active=bool(game_id),
            game_id=game_id,
        )
        loopback_mode = self._game_loopback_mode()
        if game is not None and viewer_uid is not None:
            host_uid = int(getattr(game, "host_uid", 0) or 0)
            viewer_uid = int(viewer_uid)
            target_uid = int(getattr(user, "uid", 0) or 0)
            if viewer_uid != target_uid and target_uid == host_uid and not loopback_mode:
                reachable_addr = self._reachable_host_addr_for_viewer(viewer_uid)
                adjusted = []
                for field in fields:
                    if field.startswith("A="):
                        adjusted.append(f"A={reachable_addr}")
                    elif field.startswith("LA="):
                        adjusted.append(f"LA={reachable_addr}")
                    else:
                        adjusted.append(field)
                fields = adjusted
        out = []
        for field in fields:
            if field == "F=U":
                out.append(f"F={self._onln_flag_for(user, game_active=bool(game_id))}")
            elif field == "C=":
                continue
            else:
                out.append(field)
        return out

    def _onln_name_aliases_for_user(self, user: User) -> set[str]:
        alias = self._display_name_for(user).strip()
        return {alias.lower()} if alias else set()

    def _onln_persona_aliases_for_user(self, user: User) -> set[str]:
        alias = self._persona_for(user).strip()
        return {alias.lower()} if alias else set()

    def _user_matches_onln_target(self, user: User, requested_name: str, requested_pers: str) -> bool:
        requested_name_norm = requested_name.strip().lower()
        requested_pers_norm = requested_pers.strip().lower()
        name_aliases = self._onln_name_aliases_for_user(user)
        persona_aliases = self._onln_persona_aliases_for_user(user)
        if requested_pers_norm and requested_pers_norm in (persona_aliases | name_aliases):
            return True
        if requested_name_norm and requested_name_norm in (name_aliases | persona_aliases):
            return True
        return False

    @staticmethod
    def _snapshot_matches_onln_target(snap: dict, requested_name: str, requested_pers: str) -> bool:
        requested_name_norm = requested_name.strip().lower()
        requested_pers_norm = requested_pers.strip().lower()
        snap_name = str(snap.get("name", "")).strip().lower()
        snap_pers = str(snap.get("persona", "")).strip().lower()
        if requested_pers_norm and requested_pers_norm in {snap_pers, snap_name}:
            return True
        if requested_name_norm and requested_name_norm in {snap_name, snap_pers}:
            return True
        return False

    def _snapshot_target_uid(self, game, requested_name: str, requested_pers: str) -> int:
        if game is None:
            return 0
        requested_name_norm = requested_name.strip().lower()
        requested_pers_norm = requested_pers.strip().lower()
        if not requested_name_norm and not requested_pers_norm:
            return 0
        candidates: dict[int, dict] = {}
        host_snap = self._host_snapshot(game)
        if host_snap is not None:
            candidates[int(host_snap["uid"])] = host_snap
        for uid, snap in (getattr(game, "_user_snapshots", {}) or {}).items():
            candidates[int(uid)] = snap
        for uid in getattr(game, "participants", []) or []:
            snap = self._snapshot_for_uid(game, uid)
            if snap is not None:
                candidates[int(uid)] = snap
        for uid, snap in candidates.items():
            if self._snapshot_matches_onln_target(snap, requested_name, requested_pers):
                return int(uid)
        return 0

    def _resolve_onln_target(self, game, requested_name: str, requested_pers: str, current_user: User) -> User:
        requested_name_norm = requested_name.strip().lower()
        requested_pers_norm = requested_pers.strip().lower()
        participant_uids: list[int] = []
        if game is not None:
            host_uid = int(getattr(game, "host_uid", 0) or 0)
            if host_uid:
                participant_uids.append(host_uid)
            for uid in getattr(game, "participants", []) or []:
                participant_uids.append(int(uid))
        participant_uids.append(int(current_user.uid))
        participant_uids = list(dict.fromkeys(int(uid) for uid in participant_uids if int(uid) > 0))

        if requested_name_norm or requested_pers_norm:
            for uid in participant_uids:
                candidate = current_user if int(current_user.uid) == int(uid) else self.srv.users.get(uid)
                if candidate is not None and self._user_matches_onln_target(candidate, requested_name, requested_pers):
                    return candidate
                if game is not None:
                    snap = self._snapshot_for_uid(game, uid)
                    if snap is not None and self._snapshot_matches_onln_target(snap, requested_name, requested_pers):
                        if int(current_user.uid) == int(uid):
                            return current_user
                        candidate = self.srv.users.get(uid)
                        if candidate is not None:
                            return candidate

        candidates_by_uid: dict[int, User] = {}
        for uid in participant_uids:
            candidate = current_user if int(current_user.uid) == int(uid) else self.srv.users.get(uid)
            if candidate is not None:
                candidates_by_uid[int(candidate.uid)] = candidate
        candidates = list(candidates_by_uid.values())
        if (requested_name_norm or requested_pers_norm) and len(candidates) == 2:
            if self._user_matches_onln_target(current_user, requested_name, requested_pers):
                return current_user
            for candidate in candidates:
                if int(candidate.uid) != int(current_user.uid):
                    return candidate

        snap_uid = self._snapshot_target_uid(game, requested_name, requested_pers)
        if snap_uid:
            candidate = self.srv.users.get(snap_uid)
            if candidate is not None:
                return candidate
            if int(current_user.uid) == int(snap_uid):
                return current_user
        global_candidates: dict[int, User] = {}
        for candidate in self.srv.users.all_users():
            if not getattr(candidate, "connected", False):
                continue
            global_candidates[int(candidate.uid)] = candidate
        if requested_pers_norm:
            for candidate in global_candidates.values():
                if self._user_matches_onln_target(candidate, "", requested_pers):
                    return candidate
        if requested_name_norm:
            for candidate in global_candidates.values():
                if self._user_matches_onln_target(candidate, requested_name, ""):
                    return candidate
        if game is not None and len(candidates) == 2 and (requested_name_norm or requested_pers_norm):
            for candidate in candidates:
                if int(candidate.uid) != int(current_user.uid):
                    return candidate
        return current_user

    @staticmethod
    def _sst_fields(*, uil: int = 0, uir: int = 0, uig: int = 0, gip: int = 0, gcr: int = 0, gcm: int = 0):
        fields = [
            f"GCR={gcr}",
            f"UIL={uil}",
            f"UIR={uir}",
            f"GIP={gip}",
        ]
        if uig:
            fields.append(f"UIG={uig}")
        if gcm:
            fields.append(f"GCM={gcm}")
        return fields

    def _sst_presence_fields(
        self,
        *,
        uil: int | None = None,
        uir: int | None = None,
        uig: int | None = None,
        gip: int | None = None,
        gcr: int | None = None,
        gcm: int = 0,
    ):
        counts = self.srv.users.count()
        game_count = self._game_count(self.user)
        if uil is None:
            # The stock client appears to add the game-created indicator on top
            # of UIL in its visible aggregate, so keep UIL as the user component.
            uil = max(0, counts["total"] - game_count)
        if uir is None:
            uir = counts["rooms"]
        if uig is None:
            uig = counts["games"]
        if gip is None:
            gip = 1 if int(self.user.game or 0) else 0
        if gcr is None:
            gcr = 1 if game_count else 0
        return self._sst_fields(uil=uil, uir=uir, uig=uig, gip=gip, gcr=gcr, gcm=gcm)

    def _game_reply_fields(
        self,
        game,
        *,
        params: str,
        custflags: str,
        sysflags: str,
        viewer_uid: int | None = None,
        ready_view: bool = False,
        tunnel_addrs: bool = False,
    ):
        maxsize = max(2, int(game.limit or 4))
        host_snap = self._host_snapshot(game)
        host_name = host_snap["persona"]
        game_name = game.custom or host_name
        participants = []
        for uid in game.participants:
            snap = self._snapshot_for_uid(game, uid)
            if snap is not None:
                participants.append(snap)
        host_uid = int(getattr(game, "host_uid", 0) or 0)
        if host_uid and all(int(snap["uid"]) != host_uid for snap in participants):
            participants.insert(0, host_snap)
        if viewer_uid is not None and not ready_view:
            viewer_uid = int(viewer_uid)
            participants.sort(key=lambda snap: 0 if int(snap["uid"]) == viewer_uid else 1)
        addr_map = self._game_addr_map(game)
        count = max(1, len(participants))
        relay_host, relay_port = self._game_endpoint_for_user(self.user)
        numpart = max(1, int(getattr(game, "num_partitions", 1) or 1))
        fields = [
            f"IDENT={game.id}",
            f"WHEN={self._format_time(game.created_at)}",
            f"NAME={game_name}",
            f"HOST={host_name}",
            f"ROOM={int(getattr(game, 'room_id', 0) or 0)}",
            f"MAXSIZE={maxsize}",
            "MINSIZE=2",
            f"COUNT={count}",
            f"CUSTFLAGS={custflags}",
            f"SYSFLAGS={sysflags}",
            "EVID=0",
            "EVGID=0",
            f"NUMPART={numpart}",
        ]
        if self._include_relay_fields() and tunnel_addrs and relay_host:
            fields.append(f"RLYHOST={relay_host}")
        if self._include_relay_fields() and tunnel_addrs and int(relay_port or 0) > 0:
            fields.append(f"RLYPORT={int(relay_port)}")
        loopback_mode = self._game_loopback_mode()
        opparams: list[str] = []
        for idx, snap in enumerate(participants):
            ready_flag = _READY_OPFLAG if self._game_ready(game, int(snap["uid"])) else 0
            addr = addr_map.get(int(snap["uid"]), str(snap["addr"]))
            if (
                viewer_uid is not None
                and int(snap["uid"]) == host_uid
                and int(viewer_uid) != host_uid
                and str(addr).startswith("127.")
                and not loopback_mode
            ):
                addr = self._reachable_host_addr_for_viewer(int(viewer_uid))
            laddr = addr if loopback_mode else (str(snap.get("laddr", "") or addr) if tunnel_addrs else addr)
            relay_addr = ""
            # In captured LAN room snapshots only PARAMS carries the race
            # setup; PARTPARAMS/OPPARAM are present but empty until race state.
            opparams.append(f"OPPARAM{idx}=")
            item_fields = [
                f"OPID{idx}={snap['uid']}",
                f"OPPO{idx}={snap['persona']}",
                f"ADDR{idx}={addr}",
                f"LADDR{idx}={laddr}",
                f"MADDR{idx}={relay_addr}",
                f"OPPART{idx}=0",
                f"OPFLAG{idx}={ready_flag}",
            ]
            fields.extend(
                item_fields
            )
        for idx in range(numpart):
            fields.append(f"PARTSIZE{idx}={maxsize}")
            if idx == 0:
                fields.append(f"PARAMS={params}")
            fields.append(f"PARTPARAMS{idx}=")
        fields.extend(opparams)
        return fields

    def _reachable_host_addr_for_viewer(self, viewer_uid: int) -> str:
        viewer_handler = self._handler_for_uid(int(viewer_uid))
        resolver = getattr(self.srv, "_resolve_ipv4_host", None)
        if viewer_handler is not None:
            public_addr = ""
            try:
                public_addr = str(
                    self.srv.advertised_game_host(conn=viewer_handler.user.conn) or ""
                ).strip()
            except Exception:
                public_addr = ""
            if public_addr and public_addr not in ("0.0.0.0", "::") and callable(resolver):
                try:
                    public_addr = str(resolver(public_addr) or public_addr).strip()
                except Exception:
                    pass
            if public_addr and public_addr not in ("0.0.0.0", "::") and not public_addr.startswith("127."):
                try:
                    parsed = ipaddress.ip_address(public_addr)
                except ValueError:
                    parsed = None
                if parsed is None or (not parsed.is_private and not parsed.is_loopback):
                    return public_addr
            try:
                local_addr = str(viewer_handler.user.conn.getsockname()[0] or "").strip()
            except Exception:
                local_addr = ""
            if local_addr and local_addr not in ("0.0.0.0", "::") and not local_addr.startswith("127."):
                return local_addr
        server_addr = self._server_addr()
        if server_addr and callable(resolver):
            try:
                server_addr = str(resolver(server_addr) or server_addr).strip()
            except Exception:
                pass
        if server_addr and server_addr not in ("0.0.0.0", "::") and not server_addr.startswith("127."):
            return server_addr
        detected_addr = self._detect_host_ipv4()
        if detected_addr:
            return detected_addr
        return server_addr or "127.0.0.1"

    def _game_ready_snapshot_fields(
        self,
        game,
        *,
        viewer_uid: int | None = None,
        tunnel_addrs: bool = False,
        sysflags_extra: int = 0,
    ):
        maxsize = max(2, int(game.limit or 4))
        host_uid = int(getattr(game, "host_uid", 0) or 0)
        host_snap = self._snapshot_for_uid(game, host_uid) or self._host_snapshot(game)
        host_name = host_snap["persona"]
        participants = []
        if host_snap is not None:
            participants.append(host_snap)
        for uid in game.participants:
            if int(uid) == host_uid:
                continue
            snap = self._snapshot_for_uid(game, uid)
            if snap is not None:
                participants.append(snap)
        if not participants:
            participants.append(host_snap)
        count = max(1, len(participants))
        addr_map = self._game_addr_map(game)
        loopback_mode = self._game_loopback_mode()
        relay_host, relay_port = self._game_endpoint_for_user(self.user)
        numpart = max(1, int(getattr(game, "num_partitions", 1) or 1))
        fields = [
            f"IDENT={game.id}",
            f"WHEN={self._format_time(game.created_at)}",
            f"NAME={game.custom or host_name}",
            f"HOST={host_name}",
            f"ROOM={int(getattr(game, 'room_id', 0) or 0)}",
            f"MAXSIZE={maxsize}",
            "MINSIZE=2",
            f"COUNT={count}",
            f"CUSTFLAGS={self._game_custflags(game)}",
            f"SYSFLAGS={self._game_sysflags(game, extra_bits=sysflags_extra)}",
            "EVID=0",
            "EVGID=0",
            f"NUMPART={numpart}",
        ]
        opparams: list[str] = []
        for idx, snap in enumerate(participants[:8]):
            uid = int(snap["uid"])
            addr = addr_map.get(uid, str(snap["addr"]))
            if (
                viewer_uid is not None
                and uid == host_uid
                and int(viewer_uid) != host_uid
                and str(addr).startswith("127.")
                and not loopback_mode
            ):
                addr = self._reachable_host_addr_for_viewer(int(viewer_uid))
            laddr = addr if loopback_mode else (str(snap.get("laddr", "") or addr) if tunnel_addrs else addr)
            # Keep the captured lobby/join shape: per-player params are empty
            # in +mgm/gset/gjoi even though PARAMS has the track settings.
            opparams.append(f"OPPARAM{idx}=")
            fields.extend(
                [
                    f"OPID{idx}={snap['uid']}",
                    f"OPPO{idx}={snap['persona']}",
                    f"ADDR{idx}={addr}",
                    f"LADDR{idx}={laddr}",
                    f"MADDR{idx}=",
                    f"OPPART{idx}=0",
                    f"OPFLAG{idx}={_READY_OPFLAG if self._game_ready(game, uid) else 0}",
                ]
            )
        for idx in range(numpart):
            fields.append(f"PARTSIZE{idx}={maxsize}")
            if idx == 0:
                fields.append(f"PARAMS={self._game_params(game)}")
            fields.append(f"PARTPARAMS{idx}=")
        fields.extend(opparams)
        if self._include_relay_fields() and tunnel_addrs and relay_host:
            fields.append(f"RLYHOST={relay_host}")
        if self._include_relay_fields() and tunnel_addrs and int(relay_port or 0) > 0:
            fields.append(f"RLYPORT={int(relay_port)}")
        return fields

    def _gsta_feed_fields(
        self,
        game,
        *,
        viewer_uid: int | None = None,
        tunnel_addrs: bool = False,
        sysflags_extra: int = 0,
    ):
        maxsize = max(2, int(game.limit or 4))
        host_uid = int(getattr(game, "host_uid", 0) or 0)
        host_snap = self._snapshot_for_uid(game, host_uid) or self._host_snapshot(game)
        host_name = host_snap["persona"]
        participants = []
        for uid in game.participants:
            snap = self._snapshot_for_uid(game, uid)
            if snap is not None:
                participants.append(snap)
        if host_uid and all(int(snap["uid"]) != host_uid for snap in participants):
            participants.insert(0, host_snap)
        if participants:
            if viewer_uid is not None:
                viewer_uid_int = int(viewer_uid)
                participants.sort(
                    key=lambda snap: (
                        0 if int(snap["uid"]) == viewer_uid_int else 1,
                        0 if int(snap["uid"]) == host_uid else 1,
                    )
                )
            else:
                participants.sort(key=lambda snap: 0 if int(snap["uid"]) == host_uid else 1)
        if not participants:
            participants.append(host_snap)

        count = max(1, len(participants))
        numpart = max(1, int(getattr(game, "num_partitions", 1) or 1))
        addr_map = self._game_addr_map(game)
        loopback_mode = self._game_loopback_mode()
        params = self._game_params(game)
        custflags = self._game_custflags(game)
        sysflags = self._game_sysflags(game, extra_bits=sysflags_extra)
        relay_host, relay_port = self._game_endpoint_for_user(self.user)

        fields = [
            f"IDENT={game.id}",
            f"WHEN={self._format_time(game.created_at)}",
            f"NAME={game.custom or host_name}",
            f"HOST={host_name}",
            f"ROOM={int(getattr(game, 'room_id', 0) or 0)}",
            f"MAXSIZE={maxsize}",
            "MINSIZE=2",
            f"COUNT={count}",
            f"CUSTFLAGS={custflags}",
            f"SYSFLAGS={sysflags}",
            "EVID=0",
            "EVGID=0",
            f"NUMPART={numpart}",
            f"LIMIT={maxsize}",
            f"FLAGS={custflags}",
            f"PARAMS={params}",
        ]
        if self._include_relay_fields() and tunnel_addrs and relay_host:
            fields.append(f"RLYHOST={relay_host}")
        if self._include_relay_fields() and tunnel_addrs and int(relay_port or 0) > 0:
            fields.append(f"RLYPORT={int(relay_port)}")

        for idx, snap in enumerate(participants[:8]):
            ready_flag = _READY_OPFLAG if self._game_ready(game, int(snap["uid"])) else 0
            addr = addr_map.get(int(snap["uid"]), str(snap["addr"]))
            if (
                viewer_uid is not None
                and int(snap["uid"]) == host_uid
                and int(viewer_uid) != host_uid
                and str(addr).startswith("127.")
                and not loopback_mode
            ):
                addr = self._reachable_host_addr_for_viewer(int(viewer_uid))
            laddr = addr if loopback_mode else (str(snap.get("laddr", "") or addr) if tunnel_addrs else addr)
            opparam = self._game_opparam_for(game, int(snap["uid"]))
            fields.extend(
                [
                    f"OPID{idx}={snap['uid']}",
                    f"OPPO{idx}={snap['persona']}",
                    f"ADDR{idx}={addr}",
                    f"LADDR{idx}={laddr}",
                    f"MADDR{idx}=",
                    f"OPPART{idx}=0",
                    f"OPFLAG{idx}={ready_flag}",
                    f"OPPARAM{idx}={opparam}",
                ]
            )

        for idx in range(numpart):
            fields.extend(
                [
                    f"PARTSIZE{idx}={maxsize}",
                    f"PARTPARAMS{idx}={params}",
                ]
            )
        return fields

    def _game_session_fields(self, game, *, viewer_uid: int, tunnel_addrs: bool = False):
        seed = int(getattr(game, "_seed", 11572858))
        viewer = self.srv.users.get(int(viewer_uid))
        viewer_name = self._display_name_for(viewer) if viewer is not None else ""
        fields = [
            f"IDENT={int(getattr(game, 'id', 0) or 0)}",
            f"SEED={seed}",
            f"SELF={viewer_name}",
        ]
        return fields

    def _usr_fields(self, *, sync: int, game_id: int = 0):
        return self._usr_fields_for_user(self.user, sync=sync, game_id=game_id)

    def _user_flags_for(self, user: User, *, game_id: int = 0) -> int:
        active_game_id = int(game_id or getattr(user, "game", 0) or 0)
        if active_game_id:
            game = self.srv.games.get(active_game_id)
            if game is not None and self._game_ready(game, int(user.uid)):
                return _READY_USER_FLAG
        return 0

    def _usr_fields_for_user(self, user: User, *, sync: int, game_id: int = 0, flags: int | None = None):
        if flags is None:
            flags = self._user_flags_for(user, game_id=game_id)
        game = self.srv.games.get(int(game_id)) if game_id else None
        raw_client_addr = self._client_addr_for(user)
        loopback_mode = self._game_loopback_mode()
        if game is not None:
            client_addr = self._game_addr_map(game).get(
                int(user.uid),
                self._effective_game_addr(game, int(user.uid), raw_client_addr),
            )
        else:
            client_addr = self._effective_game_addr(game, int(user.uid), raw_client_addr)
        local_addr = client_addr if loopback_mode else (raw_client_addr or client_addr)
        relay_addr = self._game_relay_addr(user)
        serv_addr = self._game_serv_addr(game) if game is not None else self._server_addr()
        raw_sprt = int(getattr(user, "sprt", 0) or getattr(user, "port", 0) or 0)
        sprt = raw_sprt
        seed = int(getattr(user, "seed", 0) or 0) << 10
        sess = str(261 + int(getattr(user, "uid", 0) or 0))
        return [
            f"IDENT={int(user.uid)}",
            f"NAME={self._display_name_for(user)}",
            f"PERS={self._persona_for(user)}",
            "UID=",
            f"ROOM={int(getattr(game, 'room_id', 0) or 0)}",
            f"GAME={game_id}",
            "STAT=",
            f"AUX={self._aux_for(user)}",
            f"RGB={self._user_rgb_for(user)}",
            "PING=2",
            "PLAY=0",
            f"SEED={seed}",
            f"FLAGS={flags}",
            f"SYNC={sync}",
            f"ADDR={client_addr}",
            f"LADDR={local_addr}",
            f"SERV={serv_addr}",
            f"SPRT={sprt}",
            f"MADDR={relay_addr}",
            "GFIDS=0",
            "ATTR=",
            "HWFLAG=0",
            "HWMASK=0",
            "LEVEL=0",
            "MEDALS=0",
            "LANG=EN",
            "FROM=US",
            f"REP={self._player_rep_for_user(user)}",
            "CRIT=",
            "SETS=",
            f"SESS={sess}",
            f"S={self._player_stat_csv_for_user(user)}",
        ]

    def _lobby_reset_usr_fields_for_user(self, user: User, *, sync: int = 4):
        usr_fields = self._usr_fields_for_user(user, sync=sync, game_id=0, flags=0)
        normalized_usr_fields: list[str] = []
        for field in usr_fields:
            if field.startswith("PING="):
                normalized_usr_fields.append("PING=1")
            elif field.startswith("FLAGS="):
                normalized_usr_fields.append("FLAGS=")
            elif field.startswith("MADDR="):
                normalized_usr_fields.append("MADDR=")
            elif field.startswith("SPRT="):
                normalized_usr_fields.append("SPRT=36010")
            else:
                normalized_usr_fields.append(field)
        return normalized_usr_fields

    def _gam_fields(self, game, *, params: str, game_key: str = "69ae6723"):
        host_user = self.srv.users.get(game.host_uid) if game.host_uid else None
        room_name = (
            game.custom
            or (self._persona_for(host_user) if host_user is not None else self._persona())
        ).replace(".", "%2e")
        count = max(1, len(game.participants))
        addr_map = self._game_addr_map(game)
        fields = [
            f"IDENT={game.id}",
            f"GAME={game.id},,40000f3,{room_name},{room_name},,,,4,2,{count},Result%20record%3a%20%25s%20vs%20%25s%20%40%20%25d,{params},{game_key},,1",
        ]
        for idx, uid in enumerate(game.participants):
            user = self.srv.users.get(uid)
            if user is None:
                continue
            client_addr = addr_map.get(int(user.uid), self._client_addr_for(user))
            if idx == 0:
                fields.append("PT0=4")
            fields.append(f"PL{idx}={self._persona_for(user)},,,,{self._ipv4_hex(client_addr)}")
        if not game.participants:
            fields.extend(["PT0=4", f"PL0={self._persona()},,,,7f000001"])
        return fields

    def _callback_fields(self) -> list[str]:
        return [
            f"CALLUSER={int(self.user.uid)}",
            "CALLPING=1",
            f"CALLADDR={self._probe_client_addr or self._client_addr_for(self.user)}",
        ]

    def _snapshot_user(self, user: User) -> dict:
        game = self.srv.games.get(int(getattr(user, "game", 0) or 0)) if getattr(user, "game", 0) else None
        raw_client_addr = self._client_addr_for(user)
        client_addr = self._effective_game_addr(game, int(user.uid), raw_client_addr)
        return {
            "uid": int(user.uid),
            "name": self._display_name_for(user),
            "persona": self._persona_for(user),
            "addr": client_addr,
            "laddr": raw_client_addr or client_addr,
            "aux": self._aux_for(user),
        }

    def _remember_game_user(self, game, user: User):
        snaps = dict(getattr(game, "_user_snapshots", {}) or {})
        snap = self._snapshot_user(user)
        snaps[int(user.uid)] = snap
        setattr(game, "_user_snapshots", snaps)
        if int(user.uid) == int(getattr(game, "host_uid", 0) or 0):
            setattr(game, "_host_snapshot", snap)

    def _snapshot_for_uid(self, game, uid: int):
        user = self.srv.users.get(uid)
        if user is not None:
            self._remember_game_user(game, user)
            return self._snapshot_user(user)
        snaps = getattr(game, "_user_snapshots", {}) or {}
        return snaps.get(int(uid))

    def _host_snapshot(self, game):
        host_uid = int(getattr(game, "host_uid", 0) or 0)
        if host_uid:
            snap = self._snapshot_for_uid(game, host_uid)
            if snap is not None:
                return snap
        snap = getattr(game, "_host_snapshot", None)
        if snap is not None:
            return snap
        host_name = (
            game.custom.split(".", 1)[-1]
            if game.custom and "." in game.custom
            else (game.custom or "HOST")
        )
        return {
            "uid": host_uid,
            "name": host_name,
            "persona": host_name,
            "addr": self._server_addr(),
            "laddr": "",
            "aux": "",
        }

    def _emit_game_presence(self, game, *, params: str, delay_s: float = 0.02, exclude_uid: int | None = None):
        handlers = self._game_handlers(game.id)
        if not handlers:
            return
        effective_params = params or self._game_params(game)
        game_frame = self._make_20922_tab_message(
            "+mgm",
            self._game_reply_fields(
                game,
                params=effective_params,
                custflags=self._game_custflags(game),
                sysflags=self._game_sysflags(game),
                tunnel_addrs=True,
            ),
        )
        who_frames = []
        for uid in game.participants:
            user = self.srv.users.get(uid)
            if user is None:
                continue
            who_frames.append(
                self._make_20922_tab_message(
                    "+who",
                    self._who_fields_for(
                        user,
                        aux_text=self._aux_for(user),
                        game_active=True,
                    ),
                )
            )
        burst = b"".join(
            who_frames + [game_frame]
        )
        for handler in handlers:
            if exclude_uid is not None and int(handler.user.uid) == int(exclude_uid):
                continue
            handler._send_later_bytes(delay_s, burst, label="game-presence")

    def _emit_join_state(self, game, joined_user: User, *, delay_s: float = 0.015):
        try:
            notify_mgm = int(self.srv.cfg.get("LAN_JOIN_NOTIFY_MGM", 0) or 0)
        except Exception:
            notify_mgm = 0
        if not notify_mgm:
            log.info(
                "[uid=%d] LAN bootstrap join-state suppressed game=%d joined_uid=%d",
                joined_user.uid,
                int(getattr(game, "id", 0) or 0),
                int(joined_user.uid),
            )
            return
        delay_s = max(float(delay_s), self._join_mgm_delay())
        for handler in self._game_handlers(game.id):
            if int(handler.user.uid) == int(joined_user.uid):
                continue
            mgm_frame = handler._make_20922_tab_message(
                "+mgm",
                handler._game_ready_snapshot_fields(
                    game,
                    viewer_uid=int(handler.user.uid),
                    tunnel_addrs=True,
                ),
            )
            handler._send_later_bytes(delay_s, mgm_frame, label="gjoi-peer-mgm")

    def _emit_join_countdown_state(self, game, *, delay_s: float):
        for handler in self._game_handlers(game.id):
            mgm_frame = handler._make_20922_tab_message(
                "+mgm",
                handler._game_ready_snapshot_fields(
                    game,
                    viewer_uid=int(handler.user.uid),
                    tunnel_addrs=True,
                    sysflags_extra=0x1000,
                ),
            )
            handler._send_later_bytes(
                delay_s,
                mgm_frame,
                label="join-countdown-mgm",
                should_send=lambda game_id=int(game.id), game_ref=game, srv=self.srv: (
                    (current := srv.games.get(game_id)) is not None
                    and current is game_ref
                    and getattr(current, "state", "") == "OPEN"
                ),
            )

    def _emit_ready_peer_state(self, game, ready_user: User, *, delay_s: float = 0.01):
        min_delay = self._ready_countdown_delay() if self._ready_countdown_enabled() else 0.01
        delay_s = max(float(delay_s), float(min_delay))
        usr_frame = self._make_20922_tab_message(
            "+usr",
            self._usr_fields_for_user(
                ready_user,
                sync=3,
                game_id=game.id,
                flags=self._user_flags_for(ready_user, game_id=game.id),
            ),
        )
        gam_frame = self._make_20922_tab_message("+gam", [f"IDENT={int(game.id)}"])
        sst_frame = self._make_20922_tab_message("+sst", self._sst_presence_fields(gcr=1))
        handlers = self._game_handlers(game.id)
        log.info(
            "[uid=%d] LAN bootstrap ready-state schedule game=%d handlers=%s",
            ready_user.uid,
            int(game.id),
            [
                f"uid={int(h.user.uid)} game={int(h.user.game or 0)} connected={int(bool(h.user.connected))}"
                for h in handlers
            ],
        )
        for handler in handlers:
            if int(handler.user.uid) == int(ready_user.uid):
                continue
            # Ready needs to reach the host before its UI tears down the join view.
            should_send_ready_state = lambda game_id=int(game.id), game_ref=game, srv=self.srv: (
                (current := srv.games.get(game_id)) is not None
                and current is game_ref
                and getattr(current, "state", "") == "OPEN"
            )
            handler._send_later_bytes(delay_s, usr_frame, label="term-peer-usr", should_send=should_send_ready_state)
            handler._send_later_bytes(delay_s + 0.006, gam_frame, label="term-peer-gam", should_send=should_send_ready_state)
            handler._send_later_bytes(max(self._term_sst_delay(), delay_s), sst_frame, label="term-peer-sst", should_send=should_send_ready_state)

    def _emit_gset_peer_state(
        self,
        game,
        ready_user: User,
        *,
        delay_s: float = 0.01,
        previous_ready: bool = False,
    ):
        delay_s = max(float(delay_s), self._join_mgm_delay())
        ready_now = self._game_ready(game, int(ready_user.uid))
        for handler in self._game_handlers(game.id):
            is_self = int(handler.user.uid) == int(ready_user.uid)
            is_unready_peer = not is_self and not (ready_now or previous_ready)
            if not is_self and (ready_now or previous_ready) and not self._ready_notify_peers_enabled():
                continue
            if is_self and not (ready_now or previous_ready):
                continue
            mgm_frame = handler._make_20922_tab_message(
                "+mgm",
                handler._game_ready_snapshot_fields(
                    game,
                    viewer_uid=int(handler.user.uid),
                    tunnel_addrs=True,
                    sysflags_extra=(0x1000 if (ready_now and self._ready_countdown_enabled()) else 0),
                ),
            )
            mgm_label = "gset-self-mgm" if is_self else "gset-peer-mgm"
            if is_unready_peer:
                handler._send_bootstrap_bytes(mgm_frame)
                log.info("[uid=%d] LAN bootstrap immediate send %s len=%d", handler.user.uid, mgm_label, len(mgm_frame))
                continue
            mgm_delay_s = delay_s
            handler._send_later_bytes(
                mgm_delay_s,
                mgm_frame,
                label=mgm_label,
                should_send=lambda game_id=int(game.id), game_ref=game, srv=self.srv: (
                    (current := srv.games.get(game_id)) is not None
                    and current is game_ref
                    and getattr(current, "state", "") == "OPEN"
                ),
            )

    def _emit_onln_game_state(self, game, requesting_user: User, *, delay_s: float = 0.006):
        game_id = int(getattr(game, "id", 0) or 0)
        request_uid = int(getattr(requesting_user, "uid", 0) or 0)
        if game_id <= 0 or request_uid <= 0:
            return
        should_send_open = lambda game_id=game_id, game_ref=game, srv=self.srv: (
            (current := srv.games.get(game_id)) is not None
            and current is game_ref
            and getattr(current, "state", "") == "OPEN"
        )
        for handler in self._game_handlers(game_id):
            is_self = int(handler.user.uid) == request_uid
            mgm_frame = handler._make_20922_tab_message(
                "+mgm",
                handler._game_ready_snapshot_fields(
                    game,
                    viewer_uid=int(handler.user.uid),
                    tunnel_addrs=True,
                ),
            )
            handler._send_later_bytes(
                delay_s + 0.012,
                mgm_frame,
                label="onln-self-mgm" if is_self else "onln-peer-mgm",
                should_send=should_send_open,
            )

    def _evgi_fields(self, game):
        host_uid = int(getattr(game, "host_uid", 0) or 0)
        host_snap = self._host_snapshot(game)
        host_name = host_snap["persona"]
        maxsize = max(2, int(game.limit or 4))
        participants = []
        for uid in game.participants:
            snap = self._snapshot_for_uid(game, uid)
            if snap is not None:
                participants.append(snap)
        if host_uid and all(int(snap["uid"]) != host_uid for snap in participants):
            participants.insert(0, host_snap)
        count = max(1, len(participants))
        fields = [
            f"SIZE0={maxsize}",
            f"HOST={host_name}",
            f"OPID0={host_uid}",
            "OPPART0=0",
            "MADDR0=",
            f"MAXSIZE={maxsize}",
            "EVID=0",
            f"ADDR0={self._server_addr()}",
            f"NUMPART={count}",
            f"OPPO0={host_name}",
            "OPFLAG0=0",
            f"NAME={game.custom or host_name}",
        ]
        start_idx = 1 if participants and int(participants[0]["uid"]) == host_uid else 0
        for idx, snap in enumerate(participants[start_idx:], start=1):
            fields.extend(
                [
                    f"OPID{idx}={snap['uid']}",
                    f"OPPART{idx}=0",
                    f"OPPO{idx}={snap['persona']}",
                    f"ADDR{idx}={snap['addr']}",
                    f"LADDR{idx}={snap['laddr']}",
                    f"MADDR{idx}=",
                    "OPFLAG{idx}=0".replace("{idx}", str(idx)),
                ]
            )
        return fields

    def _gcm_burst(self, *, gcr: int, uil: int | None = None):
        return self._make_20922_tab_message("+sst", self._sst_presence_fields(gcr=gcr, uil=uil))

    def _wrapped_evgi(self, outer_cmd4: str, game):
        return self._make_20922_wrapped_message(outer_cmd4, "EVGI", self._evgi_fields(game))

    def _lobby_snapshot_for(self, viewer) -> bytes:
        chunks = []
        for game in self._visible_games_for_user(viewer):
            params = self._game_params(game)
            base_fields = self._game_reply_fields(
                game,
                params=params,
                custflags=self._game_custflags(game),
                sysflags=self._game_sysflags(game),
                tunnel_addrs=(viewer.game == game.id),
            )
            if viewer.game == game.id:
                chunks.append(self._make_20922_tab_message("+mgm", base_fields))
                chunks.append(
                    self._make_20922_tab_message(
                        "+ses",
                        self._game_session_fields(
                            game,
                            viewer_uid=int(viewer.uid),
                            tunnel_addrs=True,
                        ),
                    )
                )
                chunks.append(self._gcm_burst(gcr=1, uil=2))
            else:
                chunks.append(self._make_20922_tab_message("+gam", base_fields))
        return b"".join(chunks)

    def _send_later_lobby_snapshot(self, handler, delay_s: float, *, label: str = "lobby-snapshot"):
        def _job():
            if not handler.user.connected or not handler.srv.is_running:
                return
            if int(getattr(handler.user, "game", 0) or 0) > 0 or str(getattr(handler.user, "stat", "") or "") == STAT_GAME:
                return
            burst = handler._lobby_snapshot_for(handler.user)
            if not burst:
                return
            handler._send_bootstrap_bytes(burst, label=label)
            if label:
                log.info("[uid=%d] LAN bootstrap delayed send %s len=%d", handler.user.uid, label, len(burst))

        timer = threading.Timer(delay_s, _job)
        timer.daemon = True
        timer.start()

    def _broadcast_lobby_snapshot(
        self,
        *,
        delay_s: float = 0.02,
        exclude_uid: int | None = None,
        with_gcm: bool = False,
    ):
        for handler in self._snapshot_handlers():
            if not handler.user.connected:
                continue
            if exclude_uid is not None and int(handler.user.uid) == int(exclude_uid):
                continue
            burst = handler._lobby_snapshot_for(handler.user)
            if burst:
                self._send_later_lobby_snapshot(handler, delay_s, label="lobby-snapshot")
            if with_gcm and handler._game_count(handler.user):
                handler._send_later_bytes(
                    delay_s + 0.02,
                    handler._gcm_burst(gcr=1),
                    label="lobby-gcm",
                    should_send=lambda handler=handler: handler._game_count(handler.user) > 0,
                )

    def _emit_game_leave_reset(self, handler, game, *, delay_s: float = 0.02, self_leave: bool = False):
        if not handler.user.connected:
            return

        game_name = ""
        if game is not None:
            game_name = str(getattr(game, "custom", "") or "").strip()
        leave_fields = [f"NAME={game_name}"] if game_name else []
        lead_frames = []
        if not self_leave and game_name:
            kick_fields = list(leave_fields)
            target_name = handler._persona_for(handler.user)
            if target_name:
                kick_fields.append(f"KICK={target_name}")
            msg_fields = handler._msg_fields(
                handler._quote_msg_text("The room is no longer available."),
                sender="Server",
                flag="U",
            )
            lead_frames.append(handler._make_20922_tab_message("gset", kick_fields))
            lead_frames.append(handler._make_20922_tab_message("+msg", msg_fields))
            lead_frames.append(handler._make_20922_tab_message("KICK", []))
        lead_frames.append(handler._make_20922_tab_message("gdel", leave_fields))
        lead_frames.append(handler._make_20922_tab_message("glea", leave_fields))
        burst = b"".join(
            (
                *lead_frames,
                handler._make_20922_tab_message(
                    "+usr",
                    handler._usr_fields_for_user(handler.user, sync=4, game_id=0),
                ),
                handler._make_20922_tab_message(
                    "+who",
                    handler._who_fields(
                        aux_text=handler._aux_for(handler.user),
                        game_active=False,
                    ),
                ),
                handler._lobby_snapshot_for(handler.user),
                handler._make_20922_tab_message("IDEN", []),
                handler._make_20922_tab_message(
                    "+sst",
                    handler._sst_presence_fields(gip=0, gcr=0),
                ),
            )
        )
        if burst:
            label = "self-glea-reset" if self_leave else "peer-glea-reset"
            handler._send_later_bytes(delay_s, burst, label=label)

    def _removed_game_closed_frames(self, handler, game, *, ack_cmd: str = "") -> list[bytes]:
        if game is None:
            return []
        game_id = int(getattr(game, "id", 0) or 0)
        frames: list[bytes] = []
        if ack_cmd:
            frames.append(handler._make_20922_tab_message(ack_cmd[:4], []))
        frames.append(
            handler._make_20922_tab_message(
                "+who",
                handler._who_fields_for(
                    handler.user,
                    aux_text=handler._aux_for(handler.user),
                    game_active=False,
                    game_id=0,
                ),
            )
        )
        if game_id:
            frames.append(handler._make_20922_tab_message("+mgm", [f"IDENT={game_id}"]))
        frames.append(handler._make_20922_tab_message("+sst", handler._sst_presence_fields(gip=0, gcr=0)))
        return frames

    def _emit_removed_game_peer_update(self, handler, game, *, delay_s: float = 0.02):
        if not handler.user.connected:
            return
        if game is None:
            self._emit_game_leave_reset(handler, game, delay_s=delay_s)
            return

        host_uid = int(getattr(game, "host_uid", 0) or 0)
        if host_uid <= 0:
            self._emit_game_leave_reset(handler, game, delay_s=delay_s)
            return

        frames = handler._removed_game_closed_frames(handler, game)
        followup_frames = []
        try:
            parts = []
            for frame in frames + followup_frames:
                cmd4 = frame[:4].decode("ascii", errors="ignore")
                payload = frame[12:-1].decode("utf-8", errors="ignore").replace("\t", " | ")
                parts.append(f"{cmd4}:{payload}")
            log.info("[uid=%d] LAN room-closed-update payload %s", int(handler.user.uid), " || ".join(parts))
        except Exception:
            pass
        handler._send_later_bytes(delay_s, b"".join(frames), label="room-closed-update")
        if followup_frames:
            handler._send_later_bytes(delay_s + 0.03, b"".join(followup_frames), label="room-closed-followup")

    def _removed_game_tombstones(self) -> dict[str, tuple[float, object]]:
        now = time.time()
        tombstones = getattr(self.srv, "_removed_game_tombstones", None)
        if not isinstance(tombstones, dict):
            tombstones = {}
            setattr(self.srv, "_removed_game_tombstones", tombstones)
        for key, value in list(tombstones.items()):
            try:
                ts = float(value[0])
            except Exception:
                tombstones.pop(key, None)
                continue
            if now - ts > _REMOVED_GAME_TOMBSTONE_SEC:
                tombstones.pop(key, None)
        return tombstones

    def _remember_removed_game(self, game):
        if game is None:
            return
        tombstones = self._removed_game_tombstones()
        ts = time.time()
        keys = {str(int(getattr(game, "id", 0) or 0))}
        name = str(getattr(game, "custom", "") or "").strip()
        if name:
            keys.add(name)
        for key in keys:
            if key:
                tombstones[key] = (ts, game)

    def _recent_removed_game(self, name: str):
        name = str(name or "").strip()
        if not name:
            return None
        tombstone = self._removed_game_tombstones().get(name)
        if tombstone is None:
            return None
        try:
            return tombstone[1]
        except Exception:
            return None

    def _removed_game_host_snapshot_frames(self, game) -> list[bytes]:
        if game is None:
            return []
        host_uid = int(getattr(game, "host_uid", 0) or 0)
        if host_uid <= 0:
            return []
        original_participants = list(getattr(game, "participants", []) or [])
        original_ready = set(getattr(game, "ready_participants", set()) or set())
        try:
            game.participants = [host_uid]
            game.ready_participants = set()
            return [
                self._make_20922_tab_message(
                    "+gam",
                    self._gam_fields(game, params=self._game_params(game), game_key="69bc0dd5"),
                ),
                self._make_20922_tab_message(
                    "+mgm",
                    self._game_reply_fields(
                        game,
                        params=self._game_params(game),
                        custflags=self._game_custflags(game),
                        sysflags=self._game_sysflags(game),
                        tunnel_addrs=False,
                    ),
                ),
            ]
        finally:
            game.participants = original_participants
            game.ready_participants = original_ready

    def _removed_game_host_evgi_frame(self, outer_cmd4: str, game) -> bytes:
        if game is None:
            return b""
        host_uid = int(getattr(game, "host_uid", 0) or 0)
        if host_uid <= 0:
            return b""
        original_participants = list(getattr(game, "participants", []) or [])
        original_ready = set(getattr(game, "ready_participants", set()) or set())
        try:
            game.participants = [host_uid]
            game.ready_participants = set()
            return self._wrapped_evgi(outer_cmd4, game)
        finally:
            game.participants = original_participants
            game.ready_participants = original_ready

    def _postrace_self_gdel_rearm_burst(self) -> bytes:
        if not getattr(self, "_pending_postrace_self_gdel", False):
            return b""
        if self._game_count(self.user) <= 0:
            return b""
        setattr(self, "_pending_postrace_self_gdel", False)
        return b"".join(
            (
                self._make_20922_tab_message("gdel", []),
                self._make_20922_tab_message(
                    "+who",
                    self._who_fields(
                        aux_text=self._aux_for(self.user),
                        game_active=False,
                    ),
                ),
                self._lobby_snapshot_for(self.user),
                self._make_20922_tab_message("IDEN", []),
                self._make_20922_tab_message("+sst", self._sst_presence_fields(gip=0, gcr=0)),
            )
        )

    def _emit_kick_target_update(self, handler, kicked_game=None, *, delay_s: float = 0.02):
        if not handler.user.connected:
            return
        kicked_game_id = int(getattr(kicked_game, "id", 0) or 0) if kicked_game is not None else 0

        def should_send_kick_update():
            if not handler.user.connected or not handler.srv.is_running:
                return False
            current_game = int(getattr(handler.user, "game", 0) or 0)
            if current_game > 0 and (kicked_game_id <= 0 or current_game != kicked_game_id):
                return False
            current_stat = str(getattr(handler.user, "stat", "") or "")
            if current_stat == STAT_GAME and (kicked_game_id <= 0 or current_game != kicked_game_id):
                return False
            return True

        usr_fields = handler._usr_fields_for_user(handler.user, sync=4, game_id=0)
        normalized_usr_fields: list[str] = []
        for field in usr_fields:
            if field.startswith("PING="):
                normalized_usr_fields.append("PING=1")
            elif field.startswith("FLAGS="):
                normalized_usr_fields.append("FLAGS=")
            elif field.startswith("MADDR="):
                normalized_usr_fields.append("MADDR=")
            elif field.startswith("SPRT="):
                normalized_usr_fields.append("SPRT=36010")
            else:
                normalized_usr_fields.append(field)
        frames = [
            handler._make_20922_tab_message(
                "+usr",
                normalized_usr_fields,
            )
        ]
        visible_games = self._visible_games_for_user(handler.user, include_kicked=kicked_game is not None)
        if kicked_game is not None and all(int(getattr(game, "id", 0) or 0) != int(getattr(kicked_game, "id", 0) or 0) for game in visible_games):
            visible_games.append(kicked_game)
        for game in visible_games:
            frames.append(
                handler._make_20922_tab_message(
                    "+gam",
                    handler._gam_fields(game, params=self._game_params(game), game_key="69bc0dd5"),
                )
            )
        burst = b"".join(frames)
        if burst:
            try:
                parts = []
                for frame in frames:
                    cmd4 = frame[:4].decode("ascii", errors="ignore")
                    payload = frame[12:-1].decode("utf-8", errors="ignore").replace("\t", " | ")
                    parts.append(f"{cmd4}:{payload}")
                log.info("[uid=%d] LAN kick-target-update payload %s", int(handler.user.uid), " || ".join(parts))
            except Exception:
                pass
            handler._send_later_bytes(
                delay_s,
                burst,
                label="kick-target-update",
                should_send=should_send_kick_update,
            )
            followup_frames = [
                handler._make_20922_tab_message(
                    "+who",
                    handler._who_fields_for(
                        handler.user,
                        aux_text=handler._aux_for(handler.user),
                        game_active=False,
                        game_id=0,
                    ),
                )
            ]
            for game in visible_games:
                followup_frames.append(
                    handler._make_20922_tab_message(
                        "+mgm",
                        handler._game_reply_fields(
                            game,
                            params=self._game_params(game),
                            custflags=self._game_custflags(game),
                            sysflags=self._game_sysflags(game),
                            tunnel_addrs=False,
                        ),
                    )
                )
            followup = b"".join(followup_frames)
            if followup:
                handler._send_later_bytes(
                    delay_s + 0.03,
                    followup,
                    label="kick-target-followup",
                    should_send=should_send_kick_update,
                )

    def _emit_kick_target_reset(self, handler, game, *, delay_s: float = 0.01):
        if not handler.user.connected:
            return
        game_name = str(getattr(game, "custom", "") or "").strip() if game is not None else ""
        fields = [f"NAME={game_name}"] if game_name else []
        target_name = handler._persona_for(handler.user)
        kick_fields = list(fields)
        if target_name:
            kick_fields.append(f"KICK={target_name}")
        host_user = self.srv.users.get(int(getattr(game, "host_uid", 0) or 0)) if game is not None else None
        host_name = self._persona_for(host_user) if host_user is not None else self._persona()
        notice = f"You have been kicked out of the room by {host_name}"
        msg_fields = handler._msg_fields(
            self._quote_msg_text(notice),
            sender="Server",
            flag="U",
        )
        frames = [
            handler._make_20922_tab_message("gset", kick_fields),
            handler._make_20922_tab_message("+msg", msg_fields),
            handler._make_20922_tab_message(
                "+usr",
                handler._usr_fields_for_user(handler.user, sync=4, game_id=0),
            ),
            handler._make_20922_tab_message(
                "+who",
                handler._who_fields_for(
                    handler.user,
                    aux_text=handler._aux_for(handler.user),
                    game_active=False,
                    game_id=0,
                ),
            ),
            handler._make_20922_tab_message("gdel", fields),
            handler._make_20922_tab_message("glea", fields),
            handler._make_20922_tab_message("+sst", handler._sst_presence_fields(gip=0, gcr=0)),
        ]
        try:
            parts = []
            for frame in frames:
                cmd4 = frame[:4].decode("latin1", errors="replace")
                payload = frame[12:-1].decode("utf-8", errors="replace").replace("\t", " | ")
                parts.append(f"{cmd4}:{payload}")
            log.info("[uid=%d] LAN kick-target-reset payload %s", int(handler.user.uid), " || ".join(parts))
        except Exception:
            pass
        burst = b"".join(frames)
        handler._send_later_bytes(delay_s, burst, label="kick-target-reset")

    def _send_kicked_gset_reset(self, game, name: str, *, reason: str) -> None:
        game_name = str(getattr(game, "custom", "") or name or "").strip() if game is not None else str(name or "").strip()
        fields = [f"NAME={game_name}"] if game_name else []
        host_user = self.srv.users.get(int(getattr(game, "host_uid", 0) or 0)) if game is not None else None
        host_name = self._persona_for(host_user) if host_user is not None else self._persona()
        notice = f"You have been kicked out of the room by {host_name}"
        msg_fields = self._msg_fields(
            self._quote_msg_text(notice),
            sender="Server",
            flag="U",
        )
        kick_fields = list(fields)
        target_name = self._persona()
        if target_name:
            kick_fields.append(f"KICK={target_name}")
        frames = [
            self._make_20922_tab_message("gset", kick_fields),
            self._make_20922_tab_message("+msg", msg_fields),
            self._make_20922_tab_message(
                "+usr",
                self._usr_fields_for_user(self.user, sync=4, game_id=0),
            ),
            self._make_20922_tab_message("gdel", fields),
            self._make_20922_tab_message("glea", fields),
            self._make_20922_tab_message(
                "+who",
                self._who_fields_for(
                    self.user,
                    aux_text=self._aux_for(self.user),
                    game_active=False,
                    game_id=0,
                ),
            ),
            self._lobby_snapshot_for(self.user),
            self._make_20922_tab_message("IDEN", []),
            self._make_20922_tab_message("+sst", self._sst_presence_fields(gip=0, gcr=0)),
        ]
        try:
            parts = []
            for frame in frames:
                cmd4 = frame[:4].decode("latin1", errors="replace")
                payload = frame[12:-1].decode("utf-8", errors="replace").replace("\t", " | ")
                parts.append(f"{cmd4}:{payload}")
            log.info("[uid=%d] LAN kicked-reset payload %s", int(self.user.uid), " || ".join(parts))
        except Exception:
            pass
        burst = b"".join(frames)
        self._send_bootstrap_bytes(burst)
        log.info(
            "[uid=%d] LAN bootstrap plaintext cmd=gset kicked-reset len=%d game=%s reason=%s",
            self.user.uid,
            len(burst),
            game_name or "-",
            reason,
        )


    def _emit_kick_host_update(self, game, *, delay_s: float = 0.02, exclude_uid: int | None = None):
        if game is None:
            return
        fields = self._game_ready_snapshot_fields(
            game,
            viewer_uid=int(getattr(game, "host_uid", 0) or 0),
            tunnel_addrs=True,
        )
        burst = self._make_20922_tab_message("+mgm", fields)
        for handler in self._game_handlers(int(game.id)):
            if not handler.user.connected:
                continue
            if exclude_uid is not None and int(handler.user.uid) == int(exclude_uid):
                continue
            handler._send_later_bytes(delay_s, burst, label="kick-host-mgm")

    def _on_game_departure(self, game, *, departed_uid: int, removed: bool, delay_s: float = 0.03):
        if game is None:
            self._broadcast_lobby_snapshot(delay_s=delay_s)
            return

        # Flush stale UDP relay room state for this game so the next race start
        # renegotiates from a clean room instead of reusing a previous room id.
        self.srv.udp_relay_reset_room(int(getattr(game, "id", 0) or 0))

        if removed:
            self._remember_removed_game(game)
            affected_uids = list(game.participants)
            host_uid = int(getattr(game, "host_uid", 0) or 0)
            if host_uid and host_uid not in affected_uids:
                affected_uids.insert(0, host_uid)
            handlers = self._snapshot_handlers()
            for handler in handlers:
                uid = int(handler.user.uid)
                if uid == int(departed_uid):
                    continue
                if uid in affected_uids or handler.user.game == game.id or handler.user.stat != STAT_GAME:
                    if int(getattr(handler.user, "game", 0) or 0) == int(game.id):
                        handler.user.game = 0
                    if handler.user.stat == STAT_GAME:
                        handler.user.stat = STAT_ROOM if handler.user.room else STAT_LOBBY
                    self._emit_removed_game_peer_update(
                        handler,
                        game,
                        delay_s=max(0.01, delay_s - 0.01),
                    )
        else:
            self._emit_game_presence(
                game,
                params=self._game_params(game),
                delay_s=max(0.01, delay_s - 0.01),
                exclude_uid=departed_uid,
            )

        self._broadcast_lobby_snapshot(delay_s=delay_s)

    @staticmethod
    def _build_user_lmstat_payload(persona: str) -> bytes:
        lines = [
            f"PERS={persona}",
            "STAT=online",
            "LMSTAT=0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,",
            "LGAME=",
        ]
        payload = ("\n".join(lines) + "\n").encode("utf-8") + b"\x00"
        if len(payload) < 106:
            payload += b"\x00" * (106 - len(payload))
        return payload

    def _consume_probe_decrypted(self, payload: bytes) -> int:
        self._probe_recv_state, plain = self._rc4_apply_20921(self._probe_recv_state, payload)
        self._probe_plain_buf.extend(plain)
        decoded = 0
        for msg_plain in self._extract_20922_messages(self._probe_plain_buf):
            cmd = ""
            body = b""
            kv = {}
            tail = b""
            if self._looks_like_short_frame(msg_plain, 0):
                cmd = msg_plain[:8].decode("latin1", errors="replace")
            else:
                if len(msg_plain) < 12 or (not self._looks_like_20922_header(msg_plain, 0)):
                    continue
                declared = struct.unpack(">I", msg_plain[8:12])[0]
                if declared < 12 or declared > len(msg_plain):
                    continue
                cmd = msg_plain[:4].decode("latin1", errors="replace")
                body = msg_plain[12:declared]
                kv = self._parse_20922_kv(body)
                nul = body.find(b"\x00")
                if nul >= 0 and (nul + 1) < len(body):
                    tail = body[nul + 1 :]
            if cmd == "addr":
                self._probe_client_addr = kv.get("ADDR", self._probe_client_addr)
                self._probe_client_port = kv.get("PORT", self._probe_client_port)
                self.user.laddr = self._probe_client_addr or self.user.laddr
                try:
                    self.user.sprt = int(self._probe_client_port or self.user.sprt or 0)
                except Exception:
                    pass
                log.info(
                    "[uid=%d] LAN bootstrap prelogin cmd=%s addr=%s port=%s tail=%s",
                    self.user.uid,
                    cmd,
                    self._probe_client_addr or "-",
                    self._probe_client_port or "-",
                    tail[:16].hex(),
                )
                frame = self._make_20922_signed_binary_message("addr", b"\x00", 9)
                self._send_probe_echo(frame)
                log.info("[uid=%d] LAN bootstrap prelogin cmd=%s replied addr len=%d", self.user.uid, cmd, len(frame))
                decoded += 1
                continue
            if cmd == "skey":
                log.info(
                    "[uid=%d] LAN bootstrap prelogin cmd=%s tail=%s keys=%s",
                    self.user.uid,
                    cmd,
                    tail[:16].hex(),
                    ",".join(sorted(kv.keys())) if kv else "-",
                )
                frame = self._make_20922_signed_binary_message("skey", b"\x00", 9)
                self._send_probe_echo(frame)
                log.info("[uid=%d] LAN bootstrap prelogin cmd=%s replied skey len=%d", self.user.uid, cmd, len(frame))
                decoded += 1
                continue
            if cmd == "news":
                frame = self._news_burst()
                self._send_probe_echo(frame)
            log.info(
                "[uid=%d] LAN bootstrap prelogin cmd=news replied news len=%d",
                self.user.uid,
                len(frame),
            )
            decoded += 1
            continue
            if cmd == "~png":
                log.info(
                    "[uid=%d] LAN bootstrap prelogin cmd=%s ref=%s",
                    self.user.uid,
                    cmd,
                    kv.get("REF", "-"),
                )
                decoded += 1
                continue
            if cmd == "sele":
                frame = self._sele_frame()
                self._send_probe_echo(frame)
                log.info("[uid=%d] LAN bootstrap prelogin cmd=sele replied sele len=%d", self.user.uid, len(frame))
                decoded += 1
                continue
            if cmd == "auth":
                name = kv.get("NAME", "").strip() or self._probe_display_name or self.user.name
                self._probe_display_name = name
                self.user.name = name
                persona = self._probe_persona or name
                self._probe_persona = persona
                if not self._accept_auth(kv, name, persona, self._send_probe_echo):
                    decoded += 1
                    continue
                name = self._probe_display_name or name
                persona = self._probe_persona or persona
                self._cleanup_replaced_detached_users()
                self.srv.remember_control_profile(
                    name=name,
                    persona=persona,
                    client_addr=self._probe_client_addr,
                )
                frame = self._auth_frame()
                self._send_probe_echo(frame)
                log.info("[uid=%d] LAN bootstrap prelogin cmd=auth replied auth len=%d", self.user.uid, len(frame))
                decoded += 1
                continue
            if cmd == "acct":
                acct_kv = dict(kv or {})
                sess, mask = self.srv.recent_dir_challenge(self.user.ip)
                if not sess or not mask:
                    _, _, sess, mask = self._dir_fields()
                acct_kv.setdefault("SESS", sess)
                acct_kv.setdefault("MASK", mask)
                acct_kv["CHALLENGE"] = mask
                ok, reason, account, identifier = self.srv.create_account(acct_kv)
                if ok and account:
                    self._apply_auth_account(account, identifier, identifier)
                    name = self._probe_display_name or identifier
                    persona = self._probe_persona or name
                    self.srv.remember_control_profile(
                        name=name,
                        persona=persona,
                        client_addr=self._probe_client_addr,
                    )
                    frame = self._account_create_frame(reason, ok=True)
                    self._send_probe_echo(frame)
                    log.info("[uid=%d] LAN bootstrap prelogin cmd=acct replied acct len=%d", self.user.uid, len(frame))
                else:
                    frame = self._account_create_frame(reason, ok=False)
                    self._send_probe_echo(frame)
                    log.info(
                        "[uid=%d] LAN bootstrap prelogin cmd=acct rejected reason=%s len=%d",
                        self.user.uid,
                        reason,
                        len(frame),
                    )
                log.info(
                    "[uid=%d] LAN bootstrap prelogin cmd=acct result=%s id=%s",
                    self.user.uid,
                    reason,
                    (identifier or "-")[:96],
                )
                decoded += 1
                continue
            if cmd in ("pers", "cper"):
                requested = kv.get("PERS", "").strip() or self._probe_persona or self._probe_display_name
                self._probe_persona = requested
                self.user.pers = requested
                display_name = self._probe_display_name or self.user.name or requested
                if not self._claim_persona_or_reject(requested, self._send_probe_echo, cmd):
                    decoded += 1
                    continue
                if cmd == "cper" or requested.lower() not in {p.lower() for p in self._auth_personas}:
                    add_persona = getattr(self.srv, "add_account_persona", None)
                    if callable(add_persona):
                        identifier = self._auth_identifier or self._auth_mail or self._probe_display_name or self.user.name
                        if add_persona(identifier, requested):
                            if requested.lower() not in {p.lower() for p in self._auth_personas}:
                                self._auth_personas.append(requested)
                self.srv.remember_control_profile(
                    name=display_name,
                    persona=requested,
                    client_addr=self._probe_client_addr,
                )
                frame = self._pers_frame(requested, display_name, cmd_name=cmd)
                self._send_probe_echo(frame)
                log.info(
                    "[uid=%d] LAN bootstrap prelogin cmd=%s replied %s len=%d persona=%s",
                    self.user.uid,
                    cmd,
                    "cper" if cmd == "cper" else "pers",
                    len(frame),
                    requested,
                )
                decoded += 1
                continue
            if cmd == "user":
                self.srv.remember_control_profile(
                    name=self._probe_display_name or self.user.name,
                    persona=self._probe_persona or self.user.pers,
                    client_addr=self._probe_client_addr,
                )
                burst = b"".join(
                    (
                        self._user_frame(),
                        self._online_who_snapshot(include_self=True),
                        self._auxi_frame(),
                    )
                )
                self._send_probe_echo(burst)
                log.info(
                    "[uid=%d] LAN bootstrap prelogin cmd=user replied user+auxi len=%d",
                    self.user.uid,
                    len(burst),
                )
                decoded += 1
                continue
            if cmd == "snap":
                self._send_probe_echo(self._snap_burst(kv))
                decoded += 1
                continue
            if cmd == "rept":
                self._record_rept(kv, source="prelogin")
                ack = self._rept_ack_frame()
                self._send_probe_echo(ack)
                log.info("[uid=%d] LAN bootstrap prelogin cmd=rept replied len=%d", self.user.uid, len(ack))
                decoded += 1
                continue
            if cmd == "userbadc":
                log.info("[uid=%d] LAN bootstrap prelogin cmd=userbadc ack", self.user.uid)
                decoded += 1
                continue
            if cmd == "auxi":
                self._probe_aux_text = kv.get("TEXT", "").strip()
                self.user.aux = self._probe_aux_text
                frame = self._auxi_frame()
                self._send_probe_echo(frame)
                log.info("[uid=%d] LAN bootstrap prelogin cmd=auxi replied auxi len=%d", self.user.uid, len(frame))
                decoded += 1
                continue
            if cmd == "gsea":
                self._probe_gsea_seen += 1
                frames = [
                    self._make_20922_tab_message("gsea", [f"COUNT={self._game_count(self.user)}"]),
                ]
                if self._probe_gsea_seen >= 2 or self._game_count(self.user):
                    frames.append(
                            self._make_20922_tab_message(
                                "+sst",
                                self._sst_presence_fields(gcr=1 if self._game_count(self.user) else 0),
                            )
                        )
                self._send_probe_echo(b"".join(frames))
                log.info(
                    "[uid=%d] LAN bootstrap prelogin cmd=gsea replied count=%d pass=%d",
                    self.user.uid,
                    self._game_count(self.user),
                    self._probe_gsea_seen,
                )
                decoded += 1
                continue
            if cmd == "gcre":
                room_name = kv.get("NAME", "").strip() or f"007.{self._display_name()}"
                params = self._normalize_params(kv.get("PARAMS", "").strip())
                custflags = kv.get("CUSTFLAGS", "0").strip()
                sysflags = kv.get("SYSFLAGS", "0").strip()
                try:
                    limit = max(2, min(8, int(kv.get("MAXSIZE", "4") or "4")))
                except Exception:
                    limit = 4
                game = self.srv.games.create(room_id=0, host_uid=self.user.uid, limit=limit, custom=room_name)
                if game is None:
                    game = self.srv.games.get(self.user.game) if self.user.game else None
                if game is not None:
                    self.srv.udp_relay_reset_room(int(game.id), preserve_recent=False)
                    self.srv.games.join(game.id, self.user.uid)
                    self.user.game = game.id
                burst = b"".join(
                    (
                        self._make_20922_tab_message(
                            "gcre",
                            self._game_reply_fields(
                                game,
                                params=params,
                                custflags=custflags,
                                sysflags=sysflags,
                                tunnel_addrs=True,
                            ),
                        ) if game is not None else self._make_20922_tab_message("gcre", []),
                        self._make_20922_tab_message(
                            "+who",
                            self._who_fields(aux_text=self._probe_aux_text, game_active=bool(game)),
                        ),
                        self._make_20922_tab_message(
                            "+mgm",
                            self._game_reply_fields(
                                game,
                                params=params,
                                custflags=custflags,
                                sysflags=sysflags,
                                tunnel_addrs=True,
                            ),
                        ) if game is not None else self._make_20922_tab_message("+mgm", []),
                    )
                )
                self._send_probe_echo(burst)
                log.info("[uid=%d] LAN bootstrap prelogin cmd=gcre replied gcre+who+mgm", self.user.uid)
                decoded += 1
                continue
            log.info(
                "[uid=%d] LAN bootstrap prelogin cmd=%s ignored keys=%s tail=%s",
                self.user.uid,
                cmd,
                ",".join(sorted(kv.keys())) if kv else "-",
                tail[:16].hex(),
            )
        return decoded

    def _consume_probe_opaque(self, payload: bytes) -> str:
        if not payload:
            return "wait"

        chunk_len = len(payload)
        self._probe_opaque_total += chunk_len

        if self._probe_expect_post534:
            self._probe_post31_buf.extend(payload)
            log.info(
                "[uid=%d] LAN bootstrap post31 opaque chunk len=%d total=%d/534",
                self.user.uid,
                chunk_len,
                len(self._probe_post31_buf),
            )
            if len(self._probe_post31_buf) >= 534:
                # Same issue as post31: the captured raw reply depends on the
                # upstream RC4 stream position. Emit the semantic auxi(21)
                # frame on the live stream instead so the client sees a valid
                # header/body pair for the current LAN session.
                self._send_probe_20922_binary("auxi", _AUXI21_PAYLOAD)
                rem = bytes(self._probe_post31_buf[534:])
                self._probe_post31_buf.clear()
                self._probe_expect_post534 = False
                self._probe_flow = "modern47"
                log.info(
                    "[uid=%d] LAN bootstrap opaque post31 total=%d replied auxi21-live len=%d rem=%d",
                    self.user.uid,
                    534 + len(rem),
                    12 + len(_AUXI21_PAYLOAD),
                    len(rem),
                )
                if rem:
                    self._consume_probe_decrypted(rem)
                return "wait"
            return "wait"

        decoded = self._consume_probe_decrypted(payload)
        if decoded:
            self._probe_flow = "modern47"
            return "wait"

        if self._probe_flow == "unknown":
            if self._probe_opaque_total == 124:
                self._probe_flow = "legacy49"
            elif self._probe_opaque_total in (47, 48, 75, 95, 122):
                self._probe_flow = "modern47"

        if self._probe_flow == "legacy49":
            if (not self._probe_boot_sent) and self._probe_opaque_total == 124:
                for blob in (_PRE64_BOOT_21_A, _PRE64_BOOT_21_B, _PRE64_BOOT_579):
                    self.user.send_bytes(blob)
                self._probe_boot_sent = True
                self._await_probe_opaque = False
                log.info(
                    "[uid=%d] LAN bootstrap ?tic legacy burst sent total=%d",
                    self.user.uid,
                    self._probe_opaque_total,
                )
                return "boot_sent"
            return "wait"

        if self._probe_flow == "modern47":
            if (not self._logged_probe_summary) and self._probe_opaque_total >= 122:
                self._logged_probe_summary = True
                log.info(
                    "[uid=%d] LAN bootstrap ?tic modern flow total=%d (prelogin echo active, later steps unsupported)",
                    self.user.uid,
                    self._probe_opaque_total,
                )
            return "wait"

        if (not self._logged_probe_summary) and self._probe_opaque_total > 124:
            self._logged_probe_summary = True
            log.info(
                "[uid=%d] LAN bootstrap ?tic opaque total=%d (flow unresolved)",
                self.user.uid,
                self._probe_opaque_total,
            )
        return "wait"

    @staticmethod
    def _parse_plain_frame(buf: bytes):
        if len(buf) < 12:
            return None
        if buf[4:8] != b"\x00\x00\x00\x00":
            return None
        total = struct.unpack(">I", buf[8:12])[0]
        if total < 12 or total > 0x4000:
            return None
        if len(buf) < total:
            return None
        cmd = buf[:4].decode("latin1", errors="replace")
        payload = buf[12:total]
        return cmd, payload, total

    @classmethod
    def _parse_any_bootstrap_frame(cls, buf: bytes):
        if cls._looks_like_short_frame(buf, 0):
            return buf[:8].decode("latin1", errors="replace"), b"", 12
        if cls._looks_like_alt_frame(buf, 0):
            total = struct.unpack(">I", buf[8:12])[0]
            return buf[:4].decode("latin1", errors="replace"), buf[12:total], total
        return cls._parse_plain_frame(buf)

    @classmethod
    def _find_bootstrap_frame_offset(cls, buf: bytes, start: int = 0):
        if start < 0:
            start = 0
        end = max(0, len(buf) - 11)
        for off in range(start, end + 1):
            if cls._looks_like_short_frame(buf, off) or cls._looks_like_20922_header(buf, off):
                return off
            if cls._looks_like_alt_frame(buf, off):
                return off
        return None

    def _handle_bootstrap_frame(self, cmd: str, payload: bytes):
        if cmd == "@tic":
            log.info(
                "[uid=%d] LAN bootstrap %s payload=%r",
                self.user.uid,
                cmd,
                payload.rstrip(b"\x00"),
            )
            return
        if cmd == "?tic":
            log.info(
                "[uid=%d] LAN bootstrap %s payload=%r",
                self.user.uid,
                cmd,
                payload.rstrip(b"\x00"),
            )
            # Stock server does not appear to answer ?tic immediately with a
            # framed packet. It ACKs at TCP level and the client then pushes
            # the next opaque bootstrap burst (~124 bytes). Replying here with
            # our guessed @tic frame causes the stock client to disconnect.
            self._probe_opaque_total = 0
            self._probe_flow = "unknown"
            self._probe_boot_sent = False
            self._logged_probe_summary = False
            self._probe_send_state = _20922_PRELOGIN_SEND_STATE
            self._probe_recv_state = _20922_PRELOGIN_RECV_STATE
            self._probe_plain_buf.clear()
            self._probe_expect_post534 = False
            self._probe_post31_buf.clear()
            self._await_probe_opaque = True
            return
        if cmd in ("@dir", "?dir"):
            pretty = payload.rstrip(b"\x00").decode("latin1", errors="replace")
            log.info("[uid=%d] LAN bootstrap %s payload=%r", self.user.uid, cmd, pretty[:200])
            self._send_bootstrap_bytes(self._make_dir_reply())
            return
        log.info("[uid=%d] LAN bootstrap unknown cmd=%r len=%d", self.user.uid, cmd, len(payload))

    def _consume_bootstrap_frames(self, buf: bytes):
        consumed = 0
        while True:
            parsed = self._parse_any_bootstrap_frame(buf[consumed:])
            if parsed is None:
                next_off = self._find_bootstrap_frame_offset(buf, consumed + 1)
                if next_off is not None:
                    skipped = buf[consumed:next_off]
                    if skipped:
                        log.info(
                            "[uid=%d] LAN bootstrap skipped opaque prefix len=%d head=%s",
                            self.user.uid,
                            len(skipped),
                            skipped[:32].hex(),
                        )
                    consumed = next_off
                    continue
                break
            cmd, payload, total = parsed
            reserved_be32 = 0
            if self._looks_like_alt_frame(buf, consumed):
                reserved_be32 = struct.unpack(">I", buf[consumed + 4 : consumed + 8])[0]
            if cmd.startswith(("@", "?")):
                self._handle_bootstrap_frame(cmd, payload)
                consumed += total
                continue
            if cmd in ("addr", "skey", "news", "~png", "sele", "auth", "acct", "pers", "cper", "dper", "user", "snap", "userbadc", "auxi", "gsea", "gcre", "gjoi", "glea", "gdel", "gset", "gsta", "onln", "mesg", "rept", "KICK", "*ath", "*pat", "PERS", "AUXI", "GCRE", "GJOI", "GSET", "TERM", "*con", "@cnt", "@alv"):
                self._handle_plain_prelogin_frame(cmd, payload, reserved_be32=reserved_be32)
                consumed += total
                continue
            log.info("[uid=%d] LAN bootstrap unhandled cmd=%r len=%d hex=%s", self.user.uid, cmd, len(payload), payload[:32].hex())
            consumed += total
            continue
        return consumed

    def _handle_plain_prelogin_frame(self, cmd: str, payload: bytes, reserved_be32: int = 0):
        if not self._ensure_registered_user():
            return
        body = payload
        kv = self._parse_20922_kv(body)
        self._trace_incoming_frame(cmd, kv, reserved_be32=reserved_be32)
        tail = b""
        nul = body.find(b"\x00")
        if nul >= 0 and (nul + 1) < len(body):
            tail = body[nul + 1 :]

        if cmd == "*con":
            self._send_bootstrap_bytes(self._make_20922_tab_message("*con", []))
            log.info("[uid=%d] LAN bootstrap plaintext cmd=*con ack", self.user.uid)
            return

        if cmd in ("@alv", "@cnt"):
            log.info(
                "[uid=%d] LAN bootstrap plaintext cmd=%s heartbeat keys=%s",
                self.user.uid,
                cmd,
                ",".join(sorted(kv.keys())) if kv else "-",
            )
            return

        if cmd == "*ath":
            name = kv.get("NAME", "").strip() or self._probe_display_name or self.user.name
            self._probe_display_name = name
            self.user.name = name
            persona = self._probe_persona or name
            self._probe_persona = persona
            self.user.pers = persona
            if not self._claim_persona_or_reject(persona, self._send_bootstrap_bytes, cmd):
                return
            tos_value = self._tos_value("LAN_ATH_TOS", 1)
            self._send_bootstrap_bytes(
                self._make_token_tab_reply(
                    reserved_be32,
                    [
                        f"NAME={name}",
                        f"GTAG={name}",
                        f"PERSONAS={persona}",
                        "XUID=",
                        f"TOS={tos_value}",
                        "SHARE=1",
                    ],
                )
            )
            log.info(
                "[uid=%d] LAN bootstrap plaintext cmd=*ath replied token=%08x",
                self.user.uid,
                reserved_be32 & 0xFFFFFFFF,
            )
            return

        if cmd == "*pat":
            requested = kv.get("PERS", "").strip() or self._probe_persona or self._probe_display_name
            self._probe_persona = requested
            self.user.pers = requested
            display_name = self._probe_display_name or self.user.name or requested
            if not self._claim_persona_or_reject(requested, self._send_bootstrap_bytes, cmd):
                return
            self._send_bootstrap_bytes(
                self._make_token_tab_reply(
                    reserved_be32,
                    [
                        f"PERS={requested}",
                        f"NAME={display_name}",
                        "GTAG=",
                        "XUID=",
                    ],
                )
            )
            log.info(
                "[uid=%d] LAN bootstrap plaintext cmd=*pat replied token=%08x persona=%s",
                self.user.uid,
                reserved_be32 & 0xFFFFFFFF,
                requested,
            )
            return

        if cmd == "PERS":
            requested = kv.get("PERS", "").strip() or self._probe_persona or self._probe_display_name
            self._probe_persona = requested
            self.user.pers = requested
            display_name = self._probe_display_name or self.user.name or requested
            if not self._claim_persona_or_reject(requested, self._send_bootstrap_bytes, cmd):
                return
            burst = b"".join(
                (
                    self._make_token_tab_reply(
                        reserved_be32,
                        [
                            f"NAME={display_name}",
                            f"PERS={requested}",
                        ],
                    ),
                    self._make_20922_tab_message("+usr", self._usr_fields(sync=1, game_id=0)),
                )
            )
            self._send_bootstrap_bytes(burst)
            log.info("[uid=%d] LAN bootstrap plaintext cmd=PERS replied token+usr", self.user.uid)
            return

        if cmd == "addr":
            self._probe_client_addr = kv.get("ADDR", self._probe_client_addr)
            self._probe_client_port = kv.get("PORT", self._probe_client_port)
            self.user.laddr = self._probe_client_addr or self.user.laddr
            try:
                self.user.sprt = int(self._probe_client_port or self.user.sprt or 0)
            except Exception:
                pass
            log.info(
                "[uid=%d] LAN bootstrap plaintext cmd=%s addr=%s port=%s tail=%s",
                self.user.uid,
                cmd,
                self._probe_client_addr or "-",
                self._probe_client_port or "-",
                tail[:16].hex(),
            )
            frame = self._make_20922_signed_binary_message("addr", b"\x00", 9)
            if self._prelogin_burst_after_news_enabled():
                self._probe_deferred_addr_frame = frame
                log.info("[uid=%d] LAN bootstrap plaintext cmd=%s deferred addr len=%d", self.user.uid, cmd, len(frame))
                return
            self._send_bootstrap_bytes(frame)
            log.info("[uid=%d] LAN bootstrap plaintext cmd=%s replied addr len=%d", self.user.uid, cmd, len(frame))
            return

        if cmd == "skey":
            log.info(
                "[uid=%d] LAN bootstrap plaintext cmd=%s tail=%s keys=%s",
                self.user.uid,
                cmd,
                tail[:16].hex(),
                ",".join(sorted(kv.keys())) if kv else "-",
            )
            frame = self._make_20922_signed_binary_message("skey", b"\x00", 9)
            if self._prelogin_burst_after_news_enabled():
                self._probe_deferred_skey_frame = frame
                log.info("[uid=%d] LAN bootstrap plaintext cmd=%s deferred skey len=%d", self.user.uid, cmd, len(frame))
                return
            self._send_bootstrap_bytes(frame)
            log.info("[uid=%d] LAN bootstrap plaintext cmd=%s replied skey len=%d", self.user.uid, cmd, len(frame))
            return

        if cmd == "news":
            frame = self._news_burst()
            burst = b""
            if self._prelogin_burst_after_news_enabled():
                burst = self._probe_deferred_addr_frame + self._probe_deferred_skey_frame
                self._probe_deferred_addr_frame = b""
                self._probe_deferred_skey_frame = b""
            self._send_bootstrap_bytes(burst + frame)
            log.info(
                "[uid=%d] LAN bootstrap plaintext cmd=%s replied prelogin_burst=%d news len=%d",
                self.user.uid,
                cmd,
                len(burst),
                len(frame),
            )
            return

        if cmd == "~png":
            log.info(
                "[uid=%d] LAN bootstrap plaintext cmd=%s ref=%s",
                self.user.uid,
                cmd,
                kv.get("REF", "-"),
            )
            self._schedule_news_auth_followups()
            return

        if cmd == "sele":
            self._probe_seen_sele = True
            frame = self._sele_frame()
            self._send_bootstrap_bytes(frame)
            log.info("[uid=%d] LAN bootstrap plaintext cmd=sele replied sele len=%d", self.user.uid, len(frame))
            return

        if cmd == "auth":
            self._probe_seen_auth = True
            name = kv.get("NAME", "").strip() or self._probe_display_name or self.user.name
            self._probe_display_name = name
            self.user.name = name
            persona = self._probe_persona or name
            self._probe_persona = persona
            if not self._accept_auth(kv, name, persona, self._send_bootstrap_bytes):
                return
            name = self._probe_display_name or name
            persona = self._probe_persona or persona
            self.srv.remember_control_profile(
                name=name,
                persona=persona,
                client_addr=self._probe_client_addr,
            )
            frame = self._auth_frame()
            self._send_bootstrap_bytes(frame)
            if self._news_push_after_auth_enabled():
                self._schedule_news_push(label="news-push-auth")
            log.info("[uid=%d] LAN bootstrap plaintext cmd=auth replied auth len=%d", self.user.uid, len(frame))
            return

        if cmd == "acct":
            acct_kv = dict(kv or {})
            sess, mask = self.srv.recent_dir_challenge(self.user.ip)
            if not sess or not mask:
                _, _, sess, mask = self._dir_fields()
            acct_kv.setdefault("SESS", sess)
            acct_kv.setdefault("MASK", mask)
            acct_kv["CHALLENGE"] = mask
            ok, reason, account, identifier = self.srv.create_account(acct_kv)
            if ok and account:
                self._apply_auth_account(account, identifier, identifier)
                name = self._probe_display_name or identifier
                persona = self._probe_persona or name
                self.srv.remember_control_profile(
                    name=name,
                    persona=persona,
                    client_addr=self._probe_client_addr,
                )
                frame = self._account_create_frame(reason, ok=True)
                self._send_bootstrap_bytes(frame)
                log.info("[uid=%d] LAN bootstrap plaintext cmd=acct replied acct len=%d", self.user.uid, len(frame))
            else:
                frame = self._account_create_frame(reason, ok=False)
                self._send_bootstrap_bytes(frame)
                log.info(
                    "[uid=%d] LAN bootstrap plaintext cmd=acct rejected reason=%s len=%d",
                    self.user.uid,
                    reason,
                    len(frame),
                )
            log.info(
                "[uid=%d] LAN bootstrap plaintext cmd=acct result=%s id=%s",
                self.user.uid,
                reason,
                (identifier or "-")[:96],
            )
            return

        if cmd in ("pers", "cper"):
            requested = kv.get("PERS", "").strip() or self._probe_persona or self._probe_display_name
            display_name = self._probe_display_name or self.user.name or requested
            if not self._claim_persona_or_reject(requested, self._send_bootstrap_bytes, cmd):
                return
            if cmd == "cper" or requested.lower() not in {p.lower() for p in self._auth_personas}:
                add_persona = getattr(self.srv, "add_account_persona", None)
                if callable(add_persona):
                    identifier = self._auth_identifier or self._auth_mail or self._probe_display_name or self.user.name
                    if add_persona(identifier, requested) and requested.lower() not in {p.lower() for p in self._auth_personas}:
                        self._auth_personas.append(requested)
            self._probe_persona = requested
            self.user.pers = requested
            self.srv.remember_control_profile(
                name=display_name,
                persona=requested,
                client_addr=self._probe_client_addr,
            )
            frame = self._pers_frame(requested, display_name, cmd_name=cmd)
            self._send_bootstrap_bytes(frame)
            log.info(
                "[uid=%d] LAN bootstrap plaintext cmd=%s replied %s len=%d persona=%s",
                self.user.uid,
                cmd,
                "cper" if cmd == "cper" else "pers",
                len(frame),
                requested,
            )
            return

        if cmd == "dper":
            requested = kv.get("PERS", "").strip()
            remove_persona = getattr(self.srv, "remove_account_persona", None)
            ok = False
            if callable(remove_persona) and requested:
                identifier = self._auth_identifier or self._auth_mail or self._probe_display_name or self.user.name
                ok = remove_persona(identifier, requested)
                if ok:
                    self._auth_personas = [p for p in self._auth_personas if p.lower() != requested.lower()]
                    if self.user.pers and self.user.pers.lower() == requested.lower() and self._auth_personas:
                        fallback = self._auth_personas[0]
                        self._probe_persona = fallback
                        self.user.pers = fallback
            frame = self._make_20922_signed_binary_message(
                "dper",
                f"PERS={requested}\nRESULT={'0' if ok else '1'}\n".encode("utf-8") + b"\x00",
                116,
            )
            self._send_bootstrap_bytes(frame)
            log.info(
                "[uid=%d] LAN bootstrap plaintext cmd=dper persona=%r ok=%s",
                self.user.uid,
                requested,
                ok,
            )
            return

        if cmd == "user":
            self.srv.remember_control_profile(
                name=self._probe_display_name or self.user.name,
                persona=self._probe_persona or self.user.pers,
                client_addr=self._probe_client_addr,
            )
            burst = b"".join(
                (
                    self._user_frame(),
                    self._online_who_snapshot(include_self=True),
                    self._make_20922_tab_message("+sst", self._sst_presence_fields()),
                    self._auxi_frame(),
                )
            )
            self._send_bootstrap_bytes(burst)
            self._broadcast_online_who(self.user, delay_s=0.03, exclude_uid=int(self.user.uid))
            log.info(
                "[uid=%d] LAN bootstrap plaintext cmd=user replied user+who-all+sst+auxi len=%d hex=%s",
                self.user.uid,
                len(burst),
                burst.hex(),
            )
            return

        if cmd == "snap":
            self._send_bootstrap_bytes(self._snap_burst(kv))
            return

        if cmd == "userbadc":
            log.info("[uid=%d] LAN bootstrap plaintext cmd=userbadc ack", self.user.uid)
            return

        if cmd in ("auxi", "AUXI"):
            self._probe_aux_text = kv.get("TEXT", "").strip()
            self.user.aux = self._probe_aux_text
            if reserved_be32:
                burst = self._make_token_tab_reply(reserved_be32, [f"TEXT={self._probe_aux_text}"])
                later = self._make_20922_tab_message("+usr", self._usr_fields(sync=2, game_id=self.user.game))
            else:
                burst = self._make_20922_tab_message("auxi", [f"TEXT={self._probe_aux_text}"])
                later = self._make_20922_tab_message(
                    "+who",
                    self._who_fields(aux_text=self._probe_aux_text, game_active=bool(self.user.game)),
                )
            self._send_bootstrap_bytes(burst)
            self._send_later_bytes(0.04, later, label=f"{cmd.lower()}-followup")
            log.info("[uid=%d] LAN bootstrap plaintext cmd=%s replied len=%d", self.user.uid, cmd, len(burst))
            return

        if cmd == "gsea":
            # After an active-race disconnect/reconnect on the same machine we
            # can still be in the middle of detached-user replacement when the
            # first lobby refresh arrives. Force that cleanup here as well, not
            # only during auth/pers, so the first post-race refresh/create sees
            # the new session as the canonical host immediately.
            self._cleanup_replaced_detached_users()
            postrace_removed_game = self._finalize_reattached_active_game_for_lobby(reason="gsea")
            self._probe_gsea_seen += 1
            visible_game_count = self._game_count(self.user)
            frames = [
                self._make_20922_tab_message("gsea", [f"COUNT={visible_game_count}"]),
            ]
            if postrace_removed_game is not None:
                frames.extend(self._removed_game_closed_frames(self, postrace_removed_game))
            if self._probe_gsea_seen >= 2 or visible_game_count:
                frames.append(
                    self._make_20922_tab_message(
                        "+sst",
                        self._sst_presence_fields(gcr=1 if visible_game_count else 0),
                    )
                )
            immediate = b"".join(frames)
            rearm_burst = b""
            if visible_game_count:
                # Former hosts that reconnect after race end ignore the
                # synthetic leave reset when it arrives as an unsolicited lobby
                # update. Inline it with the first lobby refresh that sees a
                # game again so the client consumes the reset while it is
                # actively processing the gsea round-trip.
                rearm_burst = self._postrace_self_gdel_rearm_burst()
                if rearm_burst:
                    immediate += rearm_burst
            self._send_bootstrap_bytes(immediate)
            if visible_game_count:
                if not rearm_burst:
                    snapshot = self._lobby_snapshot_for(self.user)
                    if snapshot:
                        self._send_later_lobby_snapshot(self, 0.04, label="gsea-snapshot")
                    self._send_later_bytes(
                        0.06,
                        self._gcm_burst(gcr=1),
                        label="gsea-gcm",
                        should_send=lambda: self._game_count(self.user) > 0,
                    )
            elif len(frames) == 1:
                self._send_later_bytes(
                    0.04,
                    self._make_20922_tab_message("+sst", self._sst_presence_fields(gcr=0)),
                    label="gsea-sst-empty",
                )
            log.info(
                "[uid=%d] LAN bootstrap plaintext cmd=gsea replied count=%d pass=%d",
                self.user.uid,
                visible_game_count,
                self._probe_gsea_seen,
            )
            return

        if cmd in ("gcre", "GCRE"):
            # The first create attempt after a race can land while the old
            # active-race host/peer sessions are still being replaced. Run the
            # detached replacement pass again immediately before create so we do
            # not trip the stock "session could not be created" path on stale
            # preserved users from the previous race.
            self._cleanup_replaced_detached_users()
            room_name = kv.get("NAME", "").strip() or f"007.{self._display_name()}"
            params = self._normalize_params(kv.get("PARAMS", "").strip())
            custflags = kv.get("CUSTFLAGS", "0").strip()
            sysflags = kv.get("SYSFLAGS", "0").strip()
            try:
                limit = max(2, min(8, int(kv.get("MAXSIZE", "4") or "4")))
            except Exception:
                limit = 4
            existing_game = self.srv.games.get(self.user.game) if self.user.game else None
            existing_name = str(getattr(existing_game, "custom", "") or "").strip() if existing_game is not None else ""
            reuse_existing = bool(
                existing_game is not None
                and int(getattr(existing_game, "host_uid", 0) or 0) == int(self.user.uid)
                and getattr(existing_game, "state", "") == "OPEN"
                and existing_name == room_name
            )
            if reuse_existing:
                game = existing_game
                params = self._game_params(game)
                custflags = str(getattr(game, "_custflags", custflags) or custflags)
                sysflags = str(getattr(game, "_sysflags", sysflags) or sysflags)
                log.info(
                    "[uid=%d] LAN bootstrap duplicate gcre preserved existing game=%d requested_name=%s current_name=%s",
                    self.user.uid,
                    int(getattr(game, "id", 0) or 0),
                    room_name or "-",
                    existing_name or "-",
                )
            else:
                self._clear_stale_game_memberships(reason="gcre")
                game = self.srv.games.create(room_id=0, host_uid=self.user.uid, limit=limit, custom=room_name)
                if game is None:
                    game = self.srv.games.get(self.user.game) if self.user.game else None
            if game is not None:
                if int(self.user.uid) not in [int(uid) for uid in (getattr(game, "participants", []) or [])]:
                    self.srv.games.join(game.id, self.user.uid)
                game.set_ready(self.user.uid, False)
                self._remember_game_user(game, self.user)
                self.user.game = game.id
                self.user.stat = STAT_GAME
            frames = [self._make_token_tab_reply(reserved_be32, [])] if reserved_be32 else [self._make_20922_tab_message("gcre", [])]
            later = b""
            later_sst = b""
            if game is not None:
                setattr(game, "_params", params)
                setattr(game, "_custflags", custflags)
                setattr(game, "_sysflags", sysflags)
                self._remember_game_player_params(game, int(self.user.uid), kv, params=params)
                game_fields = self._game_reply_fields(
                    game,
                    params=params,
                    custflags=custflags,
                    sysflags=sysflags,
                    tunnel_addrs=True,
                )
                if reserved_be32:
                    frames[0] = self._make_token_tab_reply(reserved_be32, game_fields)
                    later = b"".join(
                        (
                            self._make_20922_tab_message("+usr", self._usr_fields(sync=3, game_id=game.id)),
                            self._make_20922_tab_message("+gam", self._gam_fields(game, params=params)),
                        )
                    )
                    later_sst = self._make_20922_tab_message("+sst", self._sst_presence_fields(gcr=1))
                else:
                    frames[0] = self._make_20922_tab_message("gcre", game_fields)
                    later = b"".join(
                        (
                            self._make_20922_tab_message(
                                "+who",
                                self._who_fields(aux_text=self._probe_aux_text, game_active=True),
                            ),
                            self._make_20922_tab_message("+mgm", game_fields),
                        )
                    )
            burst = b"".join(frames)
            self._send_bootstrap_bytes(burst)
            if later:
                self._send_later_bytes(0.05, later, label=f"{cmd.lower()}-followup")
            if later_sst:
                self._send_later_bytes(self._term_sst_delay(), later_sst, label=f"{cmd.lower()}-sst")
            if game is not None and not reserved_be32 and not reuse_existing:
                self._emit_game_presence(game, params=params, delay_s=0.03, exclude_uid=self.user.uid)
            if not reuse_existing:
                self._broadcast_lobby_snapshot(delay_s=0.04, exclude_uid=self.user.uid, with_gcm=True)
            self.srv.request_master_stat_refresh()
            log.info(
                "[uid=%d] LAN bootstrap plaintext cmd=%s replied len=%d token=%08x",
                self.user.uid,
                cmd,
                len(burst),
                reserved_be32 & 0xFFFFFFFF,
            )
            return

        if cmd == "GJOI":
            name = kv.get("NAME", "").strip()
            ident = 0
            call_uid = 0
            try:
                ident = int(kv.get("IDENT", "0") or "0")
            except Exception:
                ident = 0
            try:
                call_uid = int(kv.get("CALLUSER", "0") or "0")
            except Exception:
                call_uid = 0
            game = self.srv.games.get(ident) if ident else None
            if game is None and name:
                for cand in self.srv.games.list_games():
                    if (cand.custom or "").strip() == name:
                        game = cand
                        break
            joined_user = self.srv.users.get(call_uid) if call_uid else None
            if game is not None and joined_user is not None:
                if int(joined_user.uid) not in [int(uid) for uid in (getattr(game, "participants", []) or [])]:
                    self.srv.games.join(game.id, joined_user.uid)
                joined_user.game = game.id
                joined_user.stat = STAT_GAME
                game.set_ready(joined_user.uid, False)
                self._remember_game_user(game, joined_user)
            fields = []
            if game is not None:
                fields = self._game_ready_snapshot_fields(
                    game,
                    viewer_uid=int(call_uid or self.user.uid),
                    tunnel_addrs=True,
                )
            burst = self._make_token_tab_reply(reserved_be32, fields)
            self._send_bootstrap_bytes(burst)
            log.info(
                "[uid=%d] LAN bootstrap plaintext cmd=GJOI callback len=%d token=%08x game=%d calluser=%d name=%s fields=%s",
                self.user.uid,
                len(burst),
                reserved_be32 & 0xFFFFFFFF,
                int(getattr(game, "id", 0) or 0) if game is not None else 0,
                call_uid,
                name or "-",
                " | ".join(fields),
            )
            return

        if cmd == "gjoi":
            params = self._normalize_params(kv.get("PARAMS", "").strip()) if kv.get("PARAMS", "").strip() else ""
            name = kv.get("NAME", "").strip()
            ident = 0
            try:
                ident = int(kv.get("IDENT", "0") or "0")
            except Exception:
                ident = 0
            game = self.srv.games.get(ident) if ident else None
            if game is None and name:
                for cand in self.srv.games.list_games():
                    if (cand.custom or "").strip() == name:
                        game = cand
                        break
            if game is None:
                pending_game = self._pending_invite_game()
                if pending_game is not None:
                    game = pending_game
                    log.info(
                        "[uid=%d] LAN bootstrap plaintext cmd=gjoi using pending invite game=%d ident=%d name=%s from=%s invite_name=%s",
                        self.user.uid,
                        int(getattr(game, "id", 0) or 0),
                        ident,
                        name or "-",
                        getattr(self, "_pending_invite_from", "") or "-",
                        getattr(self, "_pending_invite_name", "") or "-",
                    )
            if game is not None:
                self._clear_stale_game_memberships(keep_game_id=int(game.id), reason="gjoi")
            if (
                game is not None
                and int(self.user.uid) in (getattr(game, "kicked_uids", set()) or set())
                and int(getattr(self, "_pending_invite_game_id", 0) or 0) == int(getattr(game, "id", 0) or 0)
            ):
                getattr(game, "kicked_uids", set()).discard(int(self.user.uid))
                log.info(
                    "[uid=%d] LAN bootstrap plaintext cmd=gjoi cleared kicked state from pending invite game=%d",
                    self.user.uid,
                    int(getattr(game, "id", 0) or 0),
                )
            if game is not None and int(self.user.uid) in (getattr(game, "kicked_uids", set()) or set()):
                burst = self._make_20922_tab_message("gjoi", [])
                self._send_bootstrap_bytes(burst)
                log.info(
                    "[uid=%d] LAN bootstrap plaintext cmd=gjoi blocked-kicked ident=%d name=%s game=%d",
                    self.user.uid,
                    ident,
                    name or "-",
                    int(getattr(game, "id", 0) or 0),
                )
                return
            if game is not None and self.srv.games.join(game.id, self.user.uid):
                game.set_ready(self.user.uid, False)
                self._remember_game_user(game, self.user)
                self.user.game = game.id
                self.user.stat = STAT_GAME
                self._pending_invite_game_id = 0
                self._pending_invite_from = ""
                self._pending_invite_name = ""
                if params:
                    setattr(game, "_params", params)
                self._remember_game_player_params(game, int(self.user.uid), kv, params=params)
                burst = self._make_20922_tab_message(
                    "gjoi",
                    self._game_ready_snapshot_fields(
                        game,
                        viewer_uid=int(self.user.uid),
                        tunnel_addrs=True,
                    ),
                )
                self._send_bootstrap_bytes(burst)
                burst_text = burst[12:-1].decode("utf-8", errors="ignore").replace("\t", " | ")
                self._emit_join_state(game, self.user, delay_s=0.015)
                if self._join_countdown_enabled() and len(getattr(game, "participants", []) or []) >= 2:
                    self._emit_join_countdown_state(
                        game,
                        delay_s=self._join_countdown_delay(),
                    )
                for handler in self._snapshot_handlers():
                    if not handler.user.connected or handler.user.game == game.id:
                        continue
                    if int(getattr(handler.user, "game", 0) or 0) > 0 or str(getattr(handler.user, "stat", "") or "") == STAT_GAME:
                        continue
                    snap = handler._lobby_snapshot_for(handler.user)
                    if snap:
                        self._send_later_lobby_snapshot(handler, 0.03, label="lobby-snapshot")
                    if handler._game_count(handler.user):
                        handler._send_later_bytes(
                            0.05,
                            handler._gcm_burst(gcr=1),
                            label="lobby-gcm",
                            should_send=lambda handler=handler: handler._game_count(handler.user) > 0,
                        )
                log.info(
                    "[uid=%d] LAN bootstrap plaintext cmd=gjoi joined game=%d name=%s fields=%s",
                    self.user.uid,
                    game.id,
                    game.custom or "-",
                    burst_text,
                )
                self.srv.request_master_stat_refresh()
            else:
                removed_game = self._recent_removed_game(name)
                if removed_game is None and ident:
                    removed_game = self._recent_removed_game(str(ident))
                reset_frames = []
                if removed_game is not None:
                    if int(getattr(self.user, "game", 0) or 0) == int(getattr(removed_game, "id", 0) or 0):
                        self.user.game = 0
                    if self.user.stat == STAT_GAME:
                        self.user.stat = STAT_ROOM if self.user.room else STAT_LOBBY
                    reset_frames.extend(self._removed_game_closed_frames(self, removed_game))
                burst = self._make_20922_tab_message("gjoi", []) + b"".join(reset_frames)
                self._send_bootstrap_bytes(burst)
                log.info(
                    "[uid=%d] LAN bootstrap plaintext cmd=gjoi no-match ident=%d name=%s removed_game=%d",
                    self.user.uid,
                    ident,
                    name or "-",
                    int(getattr(removed_game, "id", 0) or 0) if removed_game is not None else 0,
                )
            return

        if cmd in ("glea", "gdel"):
            game_id = int(self.user.game or 0)
            game = self.srv.games.get(game_id) if game_id else None
            if game is None:
                name = kv.get("NAME", "").strip()
                if name:
                    for cand in self.srv.games.list_games():
                        if (cand.custom or "").strip() == name:
                            game = cand
                            game_id = int(cand.id)
                            break
            game_after = None
            removed = False
            if game is not None:
                game_after, removed = self.srv.games.leave(int(game.id), self.user.uid)
            self.user.game = 0
            self.user.stat = STAT_ROOM if self.user.room else STAT_LOBBY
            removed_snapshot = game or game_after
            if removed and removed_snapshot is not None:
                burst = b"".join(self._removed_game_closed_frames(self, removed_snapshot, ack_cmd=cmd))
            else:
                burst = b"".join(
                    (
                        self._make_20922_tab_message(cmd, []),
                        self._make_20922_tab_message(
                            "+who",
                            self._who_fields(aux_text=self._probe_aux_text, game_active=False),
                        ),
                        self._lobby_snapshot_for(self.user),
                        self._make_20922_tab_message("IDEN", []),
                        self._make_20922_tab_message("+sst", self._sst_presence_fields(gip=0, gcr=0)),
                    )
                )
            self._send_bootstrap_bytes(burst)
            self._on_game_departure(game or game_after, departed_uid=int(self.user.uid), removed=removed)
            self.srv.request_master_stat_refresh()
            log.info(
                "[uid=%d] LAN bootstrap plaintext cmd=%s replied len=%d game=%d removed=%d",
                self.user.uid,
                cmd,
                len(burst),
                game_id,
                int(removed),
            )
            return

        if cmd == "mesg":
            text = kv.get("TEXT", "").strip()
            attr = kv.get("ATTR", "").strip()
            priv = kv.get("PRIV", "").strip()
            ack = self._make_20922_tab_message("mesg", [f"ATTR={attr}"] if attr else [])
            self._send_bootstrap_bytes(ack)
            if bool(getattr(self.user, "muted", False)):
                reason = str(getattr(self.user, "mute_reason", "") or "").strip()
                notice = "You are muted and cannot send chat"
                if reason:
                    notice += f": {reason}"
                muted_burst = self._make_20922_tab_message(
                    "+msg",
                    self._msg_fields(notice, sender="Server", attr=attr, flag="P"),
                )
                self._send_later_bytes(0.01, muted_burst, label="msg-muted")
                log.info(
                    "[uid=%d] LAN bootstrap plaintext cmd=mesg blocked muted priv=%s attr=%s",
                    self.user.uid,
                    priv or "-",
                    attr or "-",
                )
                return
            if priv:
                target = self.srv.users.get_by_name(priv)
                if target is None:
                    target_norm = priv.strip().lower()
                    for handler in self._snapshot_handlers():
                        candidate = handler.user
                        if target_norm in {
                            self._display_name_for(candidate).strip().lower(),
                            self._persona_for(candidate).strip().lower(),
                        }:
                                target = candidate
                                break
                special_flag = attr.upper() if attr.upper().startswith("EP") else ""
                if target is not None and int(target.uid) == int(self.user.uid):
                    log.info(
                        "[uid=%d] LAN bootstrap plaintext cmd=mesg private-self ignored priv=%s attr=%s",
                        self.user.uid,
                        priv,
                        attr or "-",
                    )
                    return
                if special_flag == "EPQ":
                    self._deliver_invite(priv, text)
                sender_burst = self._make_20922_tab_message(
                    "+msg",
                    self._msg_fields(
                        text,
                        sender=f"\"To {priv}\"",
                        attr="" if special_flag else attr,
                        flag=special_flag or "PU",
                    ),
                )
                self._send_later_bytes(0.01, sender_burst, label="msg-private-self")
                target_len = 0
                if target is not None and int(target.uid) != int(self.user.uid):
                    target_handler = self._handler_for_uid(int(target.uid))
                    if target_handler is not None and target_handler.user.connected:
                        target_burst = target_handler._make_20922_tab_message(
                            "+msg",
                            target_handler._msg_fields(
                                text,
                                sender=self._persona_for(self.user),
                                attr="" if special_flag else attr,
                                flag=special_flag or "P",
                            ),
                        )
                        target_len = len(target_burst)
                        target_handler._send_later_bytes(0.01, target_burst, label="msg-private-target")
                log.info(
                    "[uid=%d] LAN bootstrap plaintext cmd=mesg private ack len=%d self=%d target=%d priv=%s attr=%s",
                    self.user.uid,
                    len(ack),
                    len(sender_burst),
                    target_len,
                    priv,
                    attr or "-",
                )
            else:
                burst = self._make_20922_tab_message(
                    "+msg",
                    self._msg_fields(text, sender=self._persona(), attr=attr),
                )
                self._broadcast_bytes(
                    burst,
                    include_self=True,
                    delay_s=0.01,
                    label="msg-broadcast",
                )
                log.info(
                    "[uid=%d] LAN bootstrap plaintext cmd=mesg ack len=%d +msg len=%d attr=%s",
                    self.user.uid,
                    len(ack),
                    len(burst),
                    attr or "-",
                )
            return

        if cmd in ("InVi", "invi", "INVI", "INVT", "GINV", "PINV"):
            target = (
                kv.get("USER", "")
                or kv.get("PERS", "")
                or kv.get("NAME", "")
                or kv.get("TARGET", "")
                or kv.get("TO", "")
            ).strip()
            text = (kv.get("TEXT", "") or kv.get("BODY", "") or kv.get("MSG", "")).strip()
            delivered = self._deliver_invite(target, text)
            fields = [f"DELIVERED={delivered}"]
            if target:
                fields.append(f"USER={target}")
            self._send_bootstrap_bytes(self._make_20922_tab_message(cmd[:4], fields))
            log.info(
                "[uid=%d] LAN bootstrap plaintext cmd=%s invite target=%s delivered=%d keys=%s",
                self.user.uid,
                cmd,
                target or "-",
                delivered,
                ",".join(sorted(kv.keys())) or "-",
            )
            return

        if cmd == "rept":
            # Stock client keeps the feedback dialog open until it sees a
            # command-level ack for this report frame.
            self._record_rept(kv, source="plaintext")
            ack = self._rept_ack_frame()
            self._send_bootstrap_bytes(ack)
            log.info("[uid=%d] LAN bootstrap plaintext cmd=rept replied len=%d", self.user.uid, len(ack))
            return

        if cmd == "KICK":
            game = self.srv.games.get(self.user.game) if self.user.game else None
            if game is None or int(getattr(game, "host_uid", 0) or 0) != int(self.user.uid):
                self._send_bootstrap_bytes(self._make_20922_tab_message("KICK", []))
                log.info(
                    "[uid=%d] LAN bootstrap plaintext cmd=KICK ignored game=%d host_uid=%d",
                    self.user.uid,
                    int(self.user.game or 0),
                    int(getattr(game, "host_uid", 0) or 0) if game is not None else 0,
                )
                return
            target = None
            target_name = kv.get("NAME", "").strip()
            target_pers = kv.get("PERS", "").strip()
            calluser = kv.get("CALLUSER", "").strip()
            effective_actor_uid = int(self.user.uid)
            target_uid = 0
            try:
                target_uid = int(kv.get("UID", "0") or "0")
            except Exception:
                target_uid = 0
            if target_uid:
                target = self.srv.users.get(target_uid)
            if target is None and calluser:
                try:
                    call_uid = int(calluser or "0")
                except Exception:
                    call_uid = 0
                if call_uid:
                    effective_actor_uid = call_uid
                if call_uid:
                    target = self.srv.users.get(call_uid)
            if target is None and target_name:
                target = self.srv.users.get_by_name(target_name)
            if target is None and (target_name or target_pers):
                target = self._resolve_onln_target(game, target_name, target_pers, self.user)
                if target is self.user:
                    if effective_actor_uid == int(self.user.uid):
                        target = None
            if target is self.user and effective_actor_uid == int(self.user.uid):
                target = None
            if target is None or int(getattr(target, "game", 0) or 0) != int(game.id):
                self._send_bootstrap_bytes(self._make_20922_tab_message("KICK", []))
                log.info(
                    "[uid=%d] LAN bootstrap plaintext cmd=KICK no-target name=%s pers=%s uid=%d game=%d",
                    self.user.uid,
                    target_name or "-",
                    target_pers or "-",
                    target_uid or (int(calluser) if calluser.isdigit() else 0),
                    int(game.id),
                )
                return
            game_after, removed = self.srv.games.leave(int(game.id), int(target.uid))
            target.game = 0
            target.stat = STAT_ROOM if target.room else STAT_LOBBY
            ack = self._make_20922_tab_message("KICK", [])
            self._send_bootstrap_bytes(ack)
            target_handler = self._handler_for_uid(int(target.uid))
            if target_handler is not None:
                self._emit_kick_target_reset(target_handler, game, delay_s=0.005)
                self._emit_game_leave_reset(target_handler, game, delay_s=0.01, self_leave=False)
            self._on_game_departure(game or game_after, departed_uid=int(target.uid), removed=removed)
            self.srv.request_master_stat_refresh()
            log.info(
                "[uid=%d] LAN bootstrap plaintext cmd=KICK target_uid=%d target=%s game=%d removed=%d",
                self.user.uid,
                int(target.uid),
                self._display_name_for(target),
                int(game.id),
                int(removed),
            )
            return

        if cmd == "TERM":
            game = self.srv.games.get(self.user.game) if self.user.game else None
            ready_count = 0
            previous_ready = False
            ready_countdown_enabled = self._ready_countdown_enabled()
            if game is not None:
                previous_ready = self._game_ready(game, int(self.user.uid))
                game.set_ready(self.user.uid, True)
                ready_count = len(getattr(game, "ready_participants", set()) or set())
            burst = self._make_20922_tab_message("TERM", [])
            self._send_bootstrap_bytes(burst)
            game_id = int(game.id) if game is not None else int(self.user.game or 1)
            if ready_countdown_enabled:
                ready_delay = self._ready_countdown_delay()
                self._send_later_bytes(
                    ready_delay,
                    b"".join(
                        (
                            self._make_20922_tab_message("+usr", self._usr_fields(sync=3, game_id=game_id)),
                            self._make_20922_tab_message("+gam", [f"IDENT={game_id}"]),
                        )
                    ),
                    label="term-followup",
                )
                self._send_later_bytes(
                    max(self._term_sst_delay(), ready_delay),
                    self._make_20922_tab_message("+sst", self._sst_presence_fields(gcr=0)),
                    label="term-sst",
                )
            if game is not None and not previous_ready:
                self._emit_ready_peer_state(game, self.user, delay_s=0.005)
            log.info(
                "[uid=%d] LAN bootstrap plaintext cmd=TERM replied len=%d ready=%d/%d countdown=%d",
                self.user.uid,
                len(burst),
                ready_count,
                len(game.participants) if game is not None else 0,
                int(ready_countdown_enabled),
            )
            return

        if cmd in ("gset", "GSET"):
            token_reply = cmd == "GSET" or reserved_be32

            def make_gset_reply(fields):
                if token_reply:
                    return self._make_token_tab_reply(reserved_be32, fields)
                return self._make_20922_tab_message("gset", fields)

            game = self.srv.games.get(self.user.game) if self.user.game else None
            name = kv.get("NAME", "").strip()
            if game is None and name:
                for cand in self.srv.games.list_games():
                    if (cand.custom or "").strip() == name:
                        game = cand
                        break
            if game is None and name:
                removed_game = self._recent_removed_game(name)
                if int(getattr(self.user, "game", 0) or 0):
                    self.user.game = 0
                if self.user.stat == STAT_GAME:
                    self.user.stat = STAT_ROOM if self.user.room else STAT_LOBBY
                reset_frames: list[bytes] = []
                response_fields: list[str] = []
                if removed_game is not None:
                    game_name = str(getattr(removed_game, "custom", "") or name or "").strip()
                    if game_name:
                        response_fields.append(f"NAME={game_name}")
                    reset_frames.extend(self._removed_game_closed_frames(self, removed_game))
                    removed_uids = {int(getattr(removed_game, "host_uid", 0) or 0)}
                    removed_uids.update(int(uid) for uid in list(getattr(removed_game, "participants", []) or []))
                    if int(self.user.uid) not in removed_uids:
                        reset_frames.append(
                            self._make_20922_tab_message(
                                "+usr",
                                self._room_usr_fields_for_user(self.user, game_id=0),
                            )
                        )
                else:
                    reset_frames.append(
                        self._make_20922_tab_message(
                            "+usr",
                            self._room_usr_fields_for_user(self.user, game_id=0),
                        )
                    )
                reset = b"".join(reset_frames)
                burst = make_gset_reply(response_fields) + reset
                self._send_bootstrap_bytes(burst)
                log.info(
                    "[uid=%d] LAN bootstrap plaintext cmd=%s stale-room-reset len=%d token=%08x name=%s removed_game=%d userflags=%s",
                    self.user.uid,
                    cmd,
                    len(burst),
                    reserved_be32 & 0xFFFFFFFF,
                    name,
                    int(getattr(removed_game, "id", 0) or 0) if removed_game is not None else 0,
                    kv.get("USERFLAGS", "-"),
                )
                return
            kick_name = kv.get("KICK", "").strip()
            if kick_name:
                target = None
                call_uid = 0
                try:
                    call_uid = int(kv.get("CALLUSER", "0") or "0")
                except Exception:
                    call_uid = 0
                host_uid = int(getattr(game, "host_uid", 0) or 0) if game is not None else 0
                effective_actor_uid = int(call_uid or self.user.uid)
                actor_is_host = bool(game is not None and (int(self.user.uid) == host_uid or (call_uid and call_uid == host_uid)))
                self_is_target = kick_name.strip().lower() in {
                    self._display_name().strip().lower(),
                    self._persona().strip().lower(),
                }
                if game is not None and actor_is_host:
                    target = self.srv.users.get_by_name(kick_name)
                    if target is None:
                        target = self._resolve_onln_target(game, kick_name, kick_name, self.user)
                        if target is self.user and effective_actor_uid == int(self.user.uid):
                            target = None
                if target is self.user and effective_actor_uid == int(self.user.uid):
                    target = None
                removed = False
                target_uid = 0
                if (
                    game is not None
                    and target is not None
                    and int(getattr(target, "game", 0) or 0) == int(game.id)
                ):
                    target_uid = int(target.uid)
                    if hasattr(game, "mark_kicked"):
                        game.mark_kicked(target_uid)
                    game_after, removed = self.srv.games.leave(int(game.id), target_uid)
                    target.game = 0
                    target.stat = STAT_ROOM if target.room else STAT_LOBBY
                    target_handler = self._handler_for_uid(target_uid)
                    if target_handler is not None:
                        self._emit_kick_target_update(target_handler, game_after or game, delay_s=0.005)
                    if removed:
                        self._on_game_departure(game or game_after, departed_uid=target_uid, removed=removed)
                    else:
                        self._emit_kick_host_update(game_after or game, delay_s=0.01, exclude_uid=target_uid)
                    self.srv.request_master_stat_refresh()
                    game = game_after or game
                response_fields = []
                if game is not None:
                    response_fields = self._game_ready_snapshot_fields(
                        game,
                        viewer_uid=int(self.user.uid),
                        tunnel_addrs=True,
                    )
                burst = make_gset_reply(response_fields)
                self._send_bootstrap_bytes(burst)
                if (
                    target_uid == 0
                    and game is not None
                    and self_is_target
                    and effective_actor_uid != int(self.user.uid)
                ):
                    self._emit_kick_target_update(self, game, delay_s=0.005)
                log.info(
                    "[uid=%d] LAN bootstrap plaintext cmd=%s kick len=%d token=%08x name=%s kick=%s target_uid=%d removed=%d keys=%s",
                    self.user.uid,
                    cmd,
                    len(burst),
                    reserved_be32 & 0xFFFFFFFF,
                    name or "-",
                    kick_name,
                    target_uid,
                    int(removed),
                    ",".join(sorted(kv.keys())) or "-",
                )
                return
            if game is not None:
                uid = int(getattr(self.user, "uid", 0) or 0)
                participants = {int(part_uid) for part_uid in (getattr(game, "participants", []) or [])}
                kicked = {int(part_uid) for part_uid in (getattr(game, "kicked_uids", set()) or set())}
                if uid in kicked or uid not in participants:
                    if int(getattr(self.user, "game", 0) or 0) == int(getattr(game, "id", 0) or 0):
                        self.user.game = 0
                    self.user.stat = STAT_ROOM if self.user.room else STAT_LOBBY
                    reason = "kicked" if uid in kicked else "not_participant"
                    response_fields = self._game_ready_snapshot_fields(
                        game,
                        viewer_uid=int(self.user.uid),
                        tunnel_addrs=True,
                    )
                    burst = make_gset_reply(response_fields)
                    self._send_bootstrap_bytes(burst)
                    self._emit_kick_target_update(self, game, delay_s=0.005)
                    log.info(
                        "[uid=%d] LAN bootstrap plaintext cmd=%s kicked-update len=%d token=%08x game=%s reason=%s",
                        self.user.uid,
                        cmd,
                        len(burst),
                        reserved_be32 & 0xFFFFFFFF,
                        name or str(getattr(game, "custom", "") or "-"),
                        reason,
                    )
                    return
            userflags_present = "USERFLAGS" in kv
            userflags_text = kv.get("USERFLAGS", "").strip()
            state_user = self.user
            call_uid = 0
            if cmd == "GSET":
                try:
                    call_uid = int(kv.get("CALLUSER", "0") or "0")
                except Exception:
                    call_uid = 0
                call_user = self.srv.users.get(call_uid) if call_uid else None
                if call_user is not None:
                    state_user = call_user
            callback_for_other = cmd == "GSET" and int(getattr(state_user, "uid", 0) or 0) != int(self.user.uid)
            previous_ready = False
            if game is not None:
                previous_ready = self._game_ready(game, int(state_user.uid))
            if userflags_present:
                try:
                    userflags = int(userflags_text or "0")
                except Exception:
                    userflags = 0
                ready = bool(userflags & _READY_OPFLAG)
            else:
                userflags = _READY_OPFLAG if previous_ready else 0
                ready = previous_ready
            duplicate_gset = self._is_duplicate_gset(
                game,
                name=name,
                userflags_present=userflags_present,
                userflags=userflags,
            ) if not callback_for_other else False
            ready_count = 0
            response_fields = []
            if game is not None:
                if not duplicate_gset and not callback_for_other:
                    game.set_ready(state_user.uid, ready)
                    self._remember_game_player_params(game, int(state_user.uid), kv)
                    if ready:
                        self._last_ready_at = time.time()
                ready_count = len(getattr(game, "ready_participants", set()) or set())
                response_fields = self._game_ready_snapshot_fields(
                    game,
                    viewer_uid=int(state_user.uid),
                    tunnel_addrs=True,
                    sysflags_extra=(0x1000 if (ready and self._ready_countdown_enabled()) else 0),
                )
                if not duplicate_gset and not callback_for_other:
                    self._emit_gset_peer_state(
                        game,
                        state_user,
                        delay_s=0.005,
                        previous_ready=previous_ready,
                    )
            burst = make_gset_reply(response_fields)
            self._send_bootstrap_bytes(burst)
            burst_text = burst[12:-1].decode("utf-8", errors="ignore").replace("\t", " | ")
            log.info(
                "[uid=%d] LAN bootstrap plaintext cmd=%s replied len=%d token=%08x ready=%d/%d userflags=%d userflags_present=%d duplicate=%d userpart=%s userparams=%s name=%s keys=%s fields=%s",
                self.user.uid,
                cmd,
                len(burst),
                reserved_be32 & 0xFFFFFFFF,
                ready_count,
                len(game.participants) if game is not None else 0,
                userflags,
                int(userflags_present),
                int(duplicate_gset),
                kv.get("USERPART", "-"),
                (str(kv.get("USERPARAMS", "") or "").strip() or "-"),
                name or "-",
                ",".join(sorted(kv.keys())) or "-",
                burst_text,
            )
            return

        if cmd == "onln":
            game = self.srv.games.get(self.user.game) if self.user.game else None
            requested_pers = kv.get("PERS", "").strip()
            requested_name = kv.get("NAME", "").strip()
            target_user = self._resolve_onln_target(game, requested_name, requested_pers, self.user)
            requested_name_norm = requested_name.strip().lower()
            requested_pers_norm = requested_pers.strip().lower()
            if game is not None and (requested_name_norm or requested_pers_norm):
                candidate_uids: list[int] = []
                host_uid = int(getattr(game, "host_uid", 0) or 0)
                if host_uid:
                    candidate_uids.append(host_uid)
                for uid in getattr(game, "participants", []) or []:
                    candidate_uids.append(int(uid))
                candidate_uids.append(int(self.user.uid))
                candidate_uids = list(dict.fromkeys(uid for uid in candidate_uids if int(uid) > 0))
                for uid in candidate_uids:
                    snap = self._snapshot_for_uid(game, uid)
                    candidate = self.user if int(self.user.uid) == int(uid) else self.srv.users.get(uid)
                    snap_name = str((snap or {}).get("name", "")).strip().lower()
                    snap_pers = str((snap or {}).get("persona", "")).strip().lower()
                    cand_name = ""
                    cand_pers = ""
                    if candidate is not None:
                        cand_name = self._display_name_for(candidate).strip().lower()
                        cand_pers = self._persona_for(candidate).strip().lower()
                    name_match = bool(requested_name_norm) and requested_name_norm in {snap_name, cand_name}
                    pers_match = bool(requested_pers_norm) and requested_pers_norm in {snap_pers, cand_pers}
                    if name_match or pers_match:
                        if candidate is not None:
                            target_user = candidate
                        elif int(self.user.uid) == int(uid):
                            target_user = self.user
                        break
            burst_parts = []
            self_target = int(target_user.uid) == int(self.user.uid)
            if game is not None:
                participants = [uid for uid in getattr(game, "participants", []) or []]
                host_uid = int(getattr(game, "host_uid", 0) or 0)
                if self_target:
                    burst_parts.append(
                        self._make_20922_tab_message(
                            "+who",
                            self._who_fields_for(
                                self.user,
                                aux_text=self._aux_for(self.user),
                                game_active=True,
                                game_id=int(game.id),
                            ),
                        )
                    )
                    burst_parts.append(
                        self._make_20922_tab_message(
                            "+mgm",
                            self._game_ready_snapshot_fields(
                                game,
                                viewer_uid=int(self.user.uid),
                                tunnel_addrs=True,
                            ),
                        )
                    )
                elif (requested_name or requested_pers) and len(participants) == 2:
                    for uid in participants:
                        if int(uid) != int(self.user.uid):
                            other = self.srv.users.get(uid)
                            if other is not None:
                                target_user = other
                            break
                    if int(self.user.uid) != host_uid:
                        burst_parts.append(
                            self._make_20922_tab_message(
                                "+who",
                                self._who_fields_for(
                                    self.user,
                                    aux_text=self._aux_for(self.user),
                                    game_active=True,
                                    game_id=int(game.id),
                                ),
                            )
                        )
                        burst_parts.append(
                            self._make_20922_tab_message(
                                "+mgm",
                                self._game_ready_snapshot_fields(
                                    game,
                                    viewer_uid=int(self.user.uid),
                                    tunnel_addrs=True,
                                ),
                            )
                        )
                else:
                    if int(target_user.uid) != int(self.user.uid):
                        burst_parts.append(
                            self._make_20922_tab_message(
                                "+who",
                                self._who_fields_for(
                                    target_user,
                                    aux_text=self._aux_for(target_user),
                                    game_active=True,
                                    game_id=int(game.id),
                                ),
                            )
                        )
                    burst_parts.append(
                        self._make_20922_tab_message(
                            "+mgm",
                            self._game_ready_snapshot_fields(
                                game,
                                viewer_uid=int(self.user.uid),
                                tunnel_addrs=True,
                            ),
                        )
                    )
            onln_fields = self._onln_fields_for_user(
                target_user,
                game,
                viewer_uid=int(self.user.uid),
            )
            if game is not None and not self_target:
                onln_fields = ["F=G" if field.startswith("F=") else field for field in onln_fields]
            onln_frame = self._make_20922_tab_message("onln", onln_fields)
            burst = b"".join(burst_parts)
            if burst:
                self._send_bootstrap_bytes(burst)
                self._send_later_bytes(0.01, onln_frame, label="onln-reply")
            else:
                self._send_bootstrap_bytes(onln_frame)
            if game is not None and (requested_name or requested_pers) and not self_target:
                self._emit_onln_game_state(game, self.user, delay_s=0.006)
            log.info(
                "[uid=%d] LAN bootstrap plaintext cmd=onln replied len=%d preburst=%d game=%d requested_name=%s requested_pers=%s target_uid=%d target=%s fields=%s",
                self.user.uid,
                len(onln_frame),
                len(burst),
                int(game.id) if game is not None else 0,
                requested_name or "-",
                requested_pers or "-",
                int(target_user.uid),
                self._display_name_for(target_user),
                " | ".join(onln_fields),
            )
            return

        if cmd == "gsta":
            name = kv.get("NAME", "").strip()
            game = self.srv.games.get(self.user.game) if self.user.game else None
            if game is None and name:
                for cand in self.srv.games.list_games():
                    if (cand.custom or "").strip() == name:
                        game = cand
                        break
            log.info(
                "[uid=%d] LAN bootstrap plaintext cmd=gsta request body_len=%d tail_len=%d body_hex=%s",
                self.user.uid,
                len(body),
                len(tail),
                body[:48].hex(),
            )
            # Captured good runs return a short binary gsta ack with a 9-byte
            # opaque payload (wire len 21), not a plain empty tab frame.
            gsta_payload = bytes(tail[:9]).ljust(9, b"\x00")
            burst = self._make_20922_binary_message("gsta", gsta_payload)
            self._send_bootstrap_bytes(burst)
            if game is not None:
                setattr(game, "_sysflags", "524288")
                should_start_game = getattr(game, "started_at", None) is None
                if should_start_game:
                    setattr(game, "_seed", int(time.time()) & 0xFFFFFFFF)
                host_uid = int(getattr(game, "host_uid", 0) or 0)
                for handler in self._game_handlers(game.id):
                    viewer_uid = int(handler.user.uid)
                    start_fields = handler._gsta_feed_fields(
                        game,
                        viewer_uid=viewer_uid,
                        tunnel_addrs=True,
                        sysflags_extra=0x80000,
                    )
                    session_fields = list(start_fields)
                    seed = int(getattr(game, "_seed", 11572858))
                    viewer = self.srv.users.get(viewer_uid)
                    viewer_name = handler._display_name_for(viewer) if viewer is not None else ""
                    session_fields.extend([f"SEED={seed}", f"SELF={viewer_name}"])
                    ses_frame = handler._make_20922_tab_message(
                        "+ses",
                        session_fields,
                    )
                    mgm_frame = handler._make_20922_tab_message(
                        "+mgm",
                        start_fields,
                    )
                    payload = mgm_frame + ses_frame
                    host_addr = "-"
                    host_laddr = "-"
                    peer_addr = "-"
                    peer_laddr = "-"
                    relay_addr = handler._game_relay_addr(handler.user) or "-"
                    for field in start_fields:
                        if field.startswith("ADDR0="):
                            host_addr = field[6:]
                        elif field.startswith("LADDR0="):
                            host_laddr = field[7:]
                        elif field.startswith("ADDR1="):
                            peer_addr = field[6:]
                        elif field.startswith("LADDR1="):
                            peer_laddr = field[7:]
                    log.info(
                        "[uid=%d] LAN bootstrap gsta state viewer=%d host_uid=%d host_addr=%s host_laddr=%s peer_addr=%s peer_laddr=%s relay=%s",
                        self.user.uid,
                        viewer_uid,
                        host_uid,
                        host_addr,
                        host_laddr,
                        peer_addr,
                        peer_laddr,
                        relay_addr,
                    )
                    try:
                        log.info(
                            "[uid=%d] LAN bootstrap gsta payload viewer=%d mgm=%s || ses=%s",
                            self.user.uid,
                            viewer_uid,
                            " | ".join(start_fields),
                            " | ".join(session_fields),
                        )
                    except Exception:
                        pass
                    label = "gsta-host-state" if viewer_uid == host_uid else "gsta-peer-state"
                    if handler is not self:
                        handler._send_bootstrap_bytes(burst)
                        log.info(
                            "[uid=%d] LAN bootstrap gsta send peer-ack viewer=%d len=%d",
                            self.user.uid,
                            viewer_uid,
                            len(burst),
                        )
                    # Send synchronously rather than via _send_later_bytes so the
                    # packet goes out before the host's TCP connection closes.
                    # The host typically closes TCP immediately after sending gsta,
                    # so a delayed send would find connected=False and be silently
                    # dropped — leaving the host without peer UDP address data and
                    # preventing it from sending any UDP in the race.
                    handler._send_bootstrap_bytes(payload)
                    log.info(
                        "[uid=%d] LAN bootstrap gsta send %s len=%d",
                        self.user.uid,
                        label,
                        len(payload),
                    )
                if should_start_game:
                    # Do not mark the game ACTIVE before the bootstrap room
                    # feed has actually been pushed to both participants. On
                    # same-PC runs the second instance can still be processing
                    # the final gsta/term frames for a short moment, and
                    # flipping state too early makes the peer_closed path fire
                    # before that client emits any race UDP at all.
                    try:
                        reset_udp = int(self.srv.cfg.get("UDP_RELAY_RESET_ON_GAME_START", 1) or 0) != 0
                    except Exception:
                        reset_udp = True
                    if reset_udp:
                        self.srv.udp_relay_reset_room(int(game.id), preserve_recent=False)
                    game.start()
            log.info(
                "[uid=%d] LAN bootstrap plaintext cmd=gsta replied len=%d name=%s tail=%s ack=%s",
                self.user.uid,
                len(burst),
                name or "-",
                tail[:16].hex(),
                gsta_payload.hex(),
            )
            return

        log.info(
            "[uid=%d] LAN bootstrap plaintext cmd=%s ignored keys=%s tail=%s",
            self.user.uid,
            cmd,
            ",".join(sorted(kv.keys())) if kv else "-",
            tail[:16].hex(),
        )
        return

    # ------------------------------------------------------------------ #
    # Main read loop                                                       #
    # ------------------------------------------------------------------ #

    def run(self):
        buf = b""
        self.user.conn.settimeout(60.0)
        try:
            while self.srv.is_running and self.user.connected:
                try:
                    data = self.user.conn.recv(4096)
                except Exception as exc:
                    self._disconnect_reason = f"recv_error:{exc.__class__.__name__}"
                    break
                if not data:
                    self._disconnect_reason = "peer_closed"
                    break
                if not self._raw_logged:
                    self._raw_logged = True
                    log.info("[uid=%d] raw first recv len=%d hex=%s",
                             self.user.uid, len(data), data[:128].hex())
                buf += data
                if self._bootstrap_mode:
                    if self._secure20921_step or self._looks_like_20921_secure_packet(buf, 0):
                        consumed = self._consume_secure_bootstrap(buf)
                        if consumed:
                            buf = buf[consumed:]
                            if not buf:
                                continue
                        if self._secure20921_step and self._secure20921_step < 5:
                            continue
                        if self._secure20921_step and self._looks_like_20921_secure_packet(buf, 0):
                            continue
                    consumed = self._consume_bootstrap_frames(buf)
                    if consumed:
                        buf = buf[consumed:]
                        # LAN bootstrap is multi-stage and frames may arrive in
                        # separate recv() calls (@tic first, then @dir / ?tic).
                        # Do not drop out of bootstrap mode just because the
                        # current buffer was fully consumed.
                        if not buf:
                            continue
                    if self._await_probe_opaque and buf:
                        if not self._logged_probe_opaque:
                            self._logged_probe_opaque = True
                            log.info(
                                "[uid=%d] LAN bootstrap opaque-after-?tic len=%d head=%s",
                                self.user.uid,
                                len(buf),
                                buf[:128].hex(),
                            )
                        status = self._consume_probe_opaque(buf)
                        buf = b""
                        if status == "boot_sent":
                            self._bootstrap_mode = False
                        # Stay in bootstrap mode and keep collecting until we
                        # identify the opaque prelogin branch.
                        continue
                    parsed = self._parse_any_bootstrap_frame(buf) if buf else None
                    next_off = self._find_bootstrap_frame_offset(buf, 1) if buf else None
                    if parsed is None:
                        # Keep waiting while the peer is still talking in
                        # framed bootstrap packets. As soon as the stream stops
                        # looking framed, fall through to line mode.
                        if (
                            buf.startswith((b"@", b"?"))
                            or (len(buf) >= 4 and buf[0] in (0x40, 0x3F))
                            or (len(buf) >= 8 and self._looks_like_20922_header(buf, 0))
                            or (len(buf) >= 8 and self._looks_like_alt_frame(buf, 0))
                            or (next_off is not None)
                            or (
                                8 <= len(buf) < 12
                                and self._is_printable_cmd4(buf[:4])
                                and buf[4:8] == b"\x00\x00\x00\x00"
                            )
                            or (4 <= len(buf) < 8 and self._is_printable_cmd4(buf[:4]))
                        ):
                            continue
                    self._bootstrap_mode = False
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    self._dispatch(line.decode("utf-8", errors="replace").strip())
                    self.user.touch()
            if not self.srv.is_running:
                self._disconnect_reason = "server_stopping"
            elif not self.user.connected and self._disconnect_reason == "loop_exit":
                self._disconnect_reason = "send_failed_or_marked_disconnected"
        finally:
            self._on_disconnect()

    def _dispatch(self, line: str):
        if not line:
            return
        sign, tag, fields = parse_message(line)
        log.debug("[uid=%d] <- %r", self.user.uid, line[:120])

        handlers = {
            "PING":     self._cmd_ping,
            "LOGIN":    self._cmd_login,
            "LOGOUT":   self._cmd_logout,
            "WHO":      self._cmd_who,
            "USERS":    self._cmd_users,
            "ROOMS":    self._cmd_rooms,
            "ROOM":     self._cmd_room,
            "MOVE":     self._cmd_move,
            "ATTR":     self._cmd_attr,
            "MESG":     self._cmd_mesg,
            "KICK":     self._cmd_kick,
            "PRIV":     self._cmd_priv,
            "LEAVEROOM":self._cmd_leave_room,
            "GAMES":    self._cmd_games,
            "NEWGAME":  self._cmd_new_game,
            "JOINGAME": self._cmd_join_game,
            "LEAVEGAME":self._cmd_leave_game,
            "STARTGAME":self._cmd_start_game,
            "ENDGAME":  self._cmd_end_game,
            "QUIK":     self._cmd_quickmatch,
            "MATCH":    self._cmd_match,
            "CHAL":     self._cmd_chal,
            "CHALRESP": self._cmd_chal_resp,
            "STAT":     self._cmd_stat,
            "RANK":     self._cmd_rank,
            "LEADERBOARD": self._cmd_leaderboard,
            "SRVSTAT":  self._cmd_server_stat,
            "USERSET":  self._cmd_user_set,
        }

        handler = handlers.get(tag)
        if handler:
            try:
                handler(fields)
            except Exception as e:
                log.error("Error handling %s for uid=%d: %s", tag, self.user.uid, e)
                self.user.send(encode_error(tag, 500, str(e)))
        else:
            self.user.send(encode_error(tag, 404, f"Unknown command: {tag}"))

    # ------------------------------------------------------------------ #
    # Commands                                                             #
    # ------------------------------------------------------------------ #

    def _cmd_ping(self, fields):
        self.user.send("+PING\n")

    def _cmd_login(self, fields):
        name = str(fields.get("NAME", f"Player{self.user.uid}"))
        pers = str(fields.get("PERS", name))
        lang = str(fields.get("LANG", "en"))
        hw   = str(fields.get("HWMID", ""))
        mac  = str(fields.get("MAC", ""))

        self.user.name  = name
        self.user.pers  = pers
        self.user.lang  = lang
        self.user.stat  = STAT_LOBBY

        # Anti-cheat HW registration
        if hw:
            self.srv.users.register_hw(self.user, hw, mac)

        if not self._ensure_registered_user():
            self.user.send(encode_error("LOGIN", 503, "Server full"))
            return
        conflict = self._persona_conflict(pers)
        if conflict is not None:
            log.warning(
                "[uid=%d] LOGIN rejected persona in use pers=%s already_uid=%d",
                self.user.uid,
                pers,
                int(getattr(conflict, "uid", 0) or 0),
            )
            self.user.send(encode_error("LOGIN", 409, "Persona already in use"))
            self.user.connected = False
            self._disconnect_reason = "persona_in_use:LOGIN"
            return

        self.user.send(encode_message("LOGIN",
                                      UID=self.user.uid,
                                      NAME=self.user.name,
                                      PERS=self.user.pers))
        log.info("LOGIN: PERS=%s GAMEREPT=%d", self.user.pers, self.user.play)

    def _cmd_logout(self, fields):
        self.user.send("+LOGOUT\n")
        self.user.connected = False

    def _cmd_who(self, fields):
        self.user.send(encode_user_record(self.user.to_dict()))

    def _cmd_users(self, fields):
        room_id = fields.get("ROOM", 0)
        users   = self.srv.users.all_users()
        if room_id:
            users = [u for u in users if u.room == room_id]
        for u in users:
            self.user.send(encode_user_record(u.to_dict()))
        self.user.send(f"+USERS COUNT={len(users)}\n")

    def _send_kv(self, key: str, value):
        self.user.send(f"{key}={value}\n")

    def _stock_rooms_mode(self, fields) -> bool:
        keys = {
            "USERS", "USERSETS", "GAMES", "MYGAME", "ROOMS",
            "RANKS", "MESGS", "ASYNC", "STATS",
            "USERSET0", "USERSET1", "USERSET2", "USERSET3",
        }
        return any(k in fields for k in keys)

    def _cmd_rooms(self, fields):
        if self._stock_rooms_mode(fields):
            for key in ("USERS", "USERSETS", "GAMES", "MYGAME", "ROOMS",
                        "RANKS", "MESGS", "ASYNC", "STATS"):
                if key in fields:
                    self.user.rooms_filter[key] = int(fields.get(key, 0))
            for key in ("USERSET0", "USERSET1", "USERSET2", "USERSET3"):
                if key in fields:
                    self.user.rooms_filter[key] = str(fields.get(key, ""))

            self._send_kv("GAMES", int(self.user.rooms_filter["GAMES"] > 0))
            self._send_kv("MYGAME", int(self.user.rooms_filter["MYGAME"] > 0))
            self._send_kv("ROOMS", int(self.user.rooms_filter["ROOMS"] > 0))
            self._send_kv("USERS", int(self.user.rooms_filter["USERS"] > 0))
            self._send_kv("USERSETS", int(self.user.rooms_filter["USERSETS"] > 0))
            for key in ("USERSET0", "USERSET1", "USERSET2", "USERSET3"):
                val = self.user.rooms_filter[key]
                if val:
                    self.user.send(f"{key}={val}\n")
            self._send_kv("MESGS", int(self.user.rooms_filter["MESGS"] > 0))
            self._send_kv("ASYNC", int(self.user.rooms_filter["ASYNC"] > 0))
            self._send_kv("RANKS", int(self.user.rooms_filter["RANKS"]))
            self._send_kv("STATS", int(self.user.rooms_filter["STATS"]))
            self._send_kv("SLOTS", 4)

            if self.user.rooms_filter["ROOMS"] > 0:
                rooms = self.srv.rooms.list_rooms()
                for r in rooms:
                    self.user.send(encode_room_record(r.to_dict()))
            return

        rooms = self.srv.rooms.list_rooms()
        for r in rooms:
            self.user.send(encode_room_record(r.to_dict()))
        self.user.send(f"+ROOMS COUNT={len(rooms)}\n")

    def _cmd_room(self, fields):
        """JOIN or CREATE a room."""
        room_id  = fields.get("IDENT", 0)
        name     = str(fields.get("NAME", ""))
        maxsize  = int(fields.get("MAXSIZE", 8))
        minsize  = int(fields.get("MINSIZE", 2))
        custflags= int(fields.get("CUSTFLAGS", 0))

        if room_id:
            # Join existing
            ok = self.srv.rooms.join(room_id, self.user.uid)
            if not ok:
                self.user.send(encode_error("ROOM", 403, "Room full or not found"))
                return
            room = self.srv.rooms.get(room_id)
        else:
            # Create new
            room = self.srv.rooms.create(
                name or f"{self.user.name}'s Room",
                self.user.uid, maxsize, minsize, custflags
            )
            if not room:
                self.user.send(encode_error("ROOM", 503, "Cannot create room"))
                return
            self.srv.rooms.join(room.id, self.user.uid)

        # Update user state
        if self.user.room:
            self.srv.rooms.leave(self.user.room, self.user.uid)
        self.user.room = room.id
        self.user.stat = STAT_ROOM

        self.user.send(encode_room_record(room.to_dict()))

        # Notify others in room
        self._broadcast_room(room.id,
                             encode_message("USERJOIN",
                                            ROOM=room.id,
                                            NAME=self.user.name,
                                            UID=self.user.uid),
                             exclude=self.user.uid)

    def _cmd_move(self, fields):
        room_id = int(fields.get("ROOM", fields.get("IDENT", 0)))
        if not room_id:
            self.user.send(encode_error("MOVE", 400, "Missing ROOM"))
            return
        room = self.srv.rooms.get(room_id)
        if not room:
            self.user.send(encode_error("MOVE", 404, "Room not found"))
            return
        if self.user.room and self.user.room != room_id:
            self.srv.rooms.leave(self.user.room, self.user.uid)
        ok = self.srv.rooms.join(room_id, self.user.uid)
        if not ok:
            self.user.send(encode_error("MOVE", 403, "Room full"))
            return
        self.user.room = room_id
        self.user.stat = STAT_ROOM
        self.user.send(encode_room_record(room.to_dict()))

    def _cmd_attr(self, fields):
        room = self.srv.rooms.get(self.user.room) if self.user.room else None
        if not room:
            self.user.send(encode_error("ATTR", 400, "Not in room"))
            return
        if room.host_uid != self.user.uid and room.assistant_uid != self.user.uid:
            self.user.send(encode_error("ATTR", 403, "Not room host"))
            return

        if "LIMIT" in fields:
            room.maxsize = max(1, min(int(fields["LIMIT"]), self.srv.rooms.max_size))
        if "PERSIST" in fields:
            room.persist = str(fields["PERSIST"]).upper() not in ("0", "OFF", "FALSE", "")
        if "HOST" in fields:
            host_user = self.srv.users.get_by_name(str(fields["HOST"]))
            if host_user and host_user.room == room.id:
                room.host_uid = host_user.uid
        if "AHOST" in fields:
            asst_user = self.srv.users.get_by_name(str(fields["AHOST"]))
            if asst_user and asst_user.room == room.id:
                room.assistant_uid = asst_user.uid

        self.user.send(encode_room_record(room.to_dict()))

    def _cmd_mesg(self, fields):
        text = str(fields.get("TEXT", fields.get("MESG", ""))).strip()
        if not text:
            self.user.send(encode_error("MESG", 400, "Missing TEXT"))
            return
        if bool(getattr(self.user, "muted", False)):
            reason = str(getattr(self.user, "mute_reason", "") or "").strip()
            message = "Muted users cannot send chat"
            if reason:
                message += f": {reason}"
            self.user.send(encode_error("MESG", 403, message))
            return
        if self.user.room:
            self._broadcast_room(
                self.user.room,
                encode_message("MESG",
                               NAME=self.user.name,
                               ROOM=self.user.room,
                               TEXT=text,
                               FLAGS=int(fields.get("FLAGS", 0))),
                exclude=None,
            )
        else:
            for u in self.srv.users.all_users():
                u.send(encode_message("MESG", NAME=self.user.name, TEXT=text))

    def _cmd_kick(self, fields):
        room = self.srv.rooms.get(self.user.room) if self.user.room else None
        if not room:
            self.user.send(encode_error("KICK", 400, "Not in room"))
            return
        if room.host_uid != self.user.uid and room.assistant_uid != self.user.uid:
            self.user.send(encode_error("KICK", 403, "Not room host"))
            return

        target = None
        if "NAME" in fields:
            target = self.srv.users.get_by_name(str(fields["NAME"]))
        elif "UID" in fields:
            target = self.srv.users.get(int(fields["UID"]))
        if not target or target.room != room.id:
            self.user.send(encode_error("KICK", 404, "Target not in room"))
            return

        self.srv.rooms.leave(room.id, target.uid)
        target.room = 0
        target.stat = STAT_LOBBY
        target.send(encode_message("KICK", TEXT=f"You have been kicked out of the room by {self.user.name}"))
        self._broadcast_room(
            room.id,
            encode_message("MESG", NAME="Server", TEXT=f"{target.name} has been kicked out of room by {self.user.name}"),
            exclude=None,
        )
        self.user.send("+KICK\n")

    def _cmd_priv(self, fields):
        val = str(fields.get("PRIV", "OFF")).upper()
        if val in ("ON", "OFF"):
            self.user.room_privacy = val
        self._send_kv("PRIV", 1 if self.user.room_privacy == "ON" else 0)

    def _cmd_leave_room(self, fields):
        room_id = self.user.room
        if not room_id:
            self.user.send(encode_error("LEAVEROOM", 400, "Not in a room"))
            return
        self.srv.rooms.leave(room_id, self.user.uid)
        self.user.room = 0
        self.user.stat = STAT_LOBBY
        self.user.send("+LEAVEROOM\n")
        self.srv.request_master_stat_refresh()
        self._broadcast_room(room_id,
                             encode_message("USERLEAVE",
                                            ROOM=room_id,
                                            NAME=self.user.name),
                             exclude=self.user.uid)

    def _cmd_games(self, fields):
        room_id = fields.get("ROOM", self.user.room)
        games   = self.srv.games.list_games(room_id if room_id else None)
        for g in games:
            self.user.send(encode_game_record(g.to_dict()))
        self.user.send(f"+GAMES COUNT={len(games)}\n")

    def _cmd_new_game(self, fields):
        limit   = int(fields.get("LIMIT", 8))
        gtype   = str(fields.get("TYPE", "PUBLIC"))
        flags   = float(fields.get("FLAGS", 0.0))
        secret  = str(fields.get("SECRET", ""))
        custom  = str(fields.get("CUSTOM", ""))
        fmt     = str(fields.get("FORMAT", ""))

        # PlayModuleGameCreateFilter
        if not self.srv.play.game_create_filter(self.user.uid, fields):
            self.user.send(encode_error("NEWGAME", 403, "Game creation denied"))
            return

        game = self.srv.games.create(
            room_id=self.user.room,
            host_uid=self.user.uid,
            limit=limit, game_type=gtype,
            flags=flags, secret=secret,
            custom=custom, fmt=fmt
        )
        if not game:
            self.user.send(encode_error("NEWGAME", 503, "Cannot create game"))
            return

        self.srv.games.join(game.id, self.user.uid)
        self.user.game = game.id
        self.user.stat = STAT_GAME
        self.user.send(encode_game_record(game.to_dict()))

    def _cmd_join_game(self, fields):
        game_id = int(fields.get("IDENT", 0))
        if not game_id:
            self.user.send(encode_error("JOINGAME", 400, "Missing IDENT"))
            return

        if not self.srv.play.game_join_filter(self.user.uid, game_id):
            self.user.send(encode_error("JOINGAME", 403, "Cannot join game"))
            return

        ok = self.srv.games.join(game_id, self.user.uid)
        if not ok:
            self.user.send(encode_error("JOINGAME", 403, "Game full or not found"))
            return

        self.user.game = game_id
        self.user.stat = STAT_GAME
        game = self.srv.games.get(game_id)
        self.user.send(encode_game_record(game.to_dict()))

    def _cmd_leave_game(self, fields):
        game_id = self.user.game
        if not game_id:
            self.user.send(encode_error("LEAVEGAME", 400, "Not in a game"))
            return
        game = self.srv.games.get(game_id)
        game_after, removed = self.srv.games.leave(game_id, self.user.uid)
        self.user.game = 0
        self.user.stat = STAT_ROOM if self.user.room else STAT_LOBBY
        self.user.send("+LEAVEGAME\n")
        self._emit_game_leave_reset(self, game or game_after, delay_s=0.01, self_leave=True)
        self._on_game_departure(game or game_after, departed_uid=int(self.user.uid), removed=removed)
        self.srv.request_master_stat_refresh()

    def _cmd_start_game(self, fields):
        game_id = self.user.game
        game    = self.srv.games.get(game_id) if game_id else None
        if not game or game.host_uid != self.user.uid:
            self.user.send(encode_error("STARTGAME", 403, "Not game host"))
            return
        try:
            reset_udp = int(self.srv.cfg.get("UDP_RELAY_RESET_ON_GAME_START", 1) or 0) != 0
        except Exception:
            reset_udp = True
        if reset_udp:
            self.srv.udp_relay_reset_room(int(game.id), preserve_recent=False)
        game.start()
        self._broadcast_game(game_id, f"+STARTGAME IDENT={game_id}\n")

    def _cmd_end_game(self, fields):
        """Client reports game result."""
        game_id = self.user.game
        game    = self.srv.games.get(game_id) if game_id else None
        if not game:
            self.user.send(encode_error("ENDGAME", 400, "Not in a game"))
            return

        # Parse results for each participant
        results = {}
        race_category = 0
        for race_key in ("RACETYPE", "TYPE", "MODE"):
            if race_key in fields:
                try:
                    race_category = max(0, min(4, int(fields.get(race_key, 0)) + 1))
                except Exception:
                    race_category = 0
                break
        for uid in game.participants:
            outcome = str(fields.get(f"USER{uid}_OUTCOME", "LOSS"))
            score_d = float(fields.get(f"USER{uid}_SCORE", 0.0))
            duration = float(fields.get("DURATION", 0.0))
            results[uid] = {
                "outcome":      outcome,
                "score_delta":  score_d,
                "duration":     duration,
            }
            # Update stats
            self.srv.stats.increment_stat(uid, 1, "games_played")
            if outcome == "WIN":
                self.srv.stats.increment_stat(uid, 1, "wins")
            participant = self.srv.users.get(uid)
            if participant is not None:
                self.srv.stats.record_player_result(
                    self._persona_for(participant),
                    outcome,
                    category_index=race_category,
                )

        # PlayModuleGameResultReceived
        self.srv.play.game_result_received(game_id, results)

        # Queue batch report
        report = GameReport(game_id, game.participants, results)
        self.srv.batch.enqueue(report)

        # Reset all players
        for uid in game.participants:
            u = self.srv.users.get(uid)
            if u:
                u.game = 0
                u.stat = STAT_ROOM if u.room else STAT_LOBBY
                u.play += 1
                u.send(f"+ENDGAME IDENT={game_id}\n")
        self.srv.request_master_stat_refresh()

    def _cmd_quickmatch(self, fields):
        """Enter quickmatch queue."""
        criteria              = MatchCriteria()
        criteria.min_players  = int(fields.get("MINSIZE", 2))
        criteria.max_players  = int(fields.get("MAXSIZE", 8))
        criteria.skill_min    = int(fields.get("SKILLMIN", 0))
        criteria.skill_max    = int(fields.get("SKILLMAX", 9999))
        criteria.ping_max     = int(fields.get("PINGMAX", 500))

        ok = self.srv.play.quick_join_enqueue(self.user.uid, criteria)
        if ok:
            self.user.send(f"+QUIK STATUS=QUEUED\n")
        else:
            self.user.send(f"+QUIK STATUS=ALREADY_QUEUED\n")

    def _cmd_match(self, fields):
        """Lobby-based matchmaking."""
        criteria = MatchCriteria()
        room_id  = self.srv.play.find_best_room(self.user.uid, criteria)
        if room_id:
            self.user.send(encode_message("MATCH", ROOM=room_id))
        else:
            self.user.send(encode_error("MATCH", 404, "No match found"))

    def _cmd_chal(self, fields):
        target = str(fields.get("NAME", ""))
        if not target:
            self.user.send(encode_error("CHAL", 400, "Missing NAME"))
            return
        ok, msg = self.srv.challenges.challenge(self.user.uid, target)
        if not ok:
            self.user.send(encode_error("CHAL", 403, msg))

    def _cmd_chal_resp(self, fields):
        ident  = int(fields.get("IDENT", 0))
        accept = str(fields.get("STATUS", "REJECT")).upper() == "ACCEPT"
        self.srv.challenges.respond(ident, self.user.uid, accept)

    def _cmd_stat(self, fields):
        """Get or set a stat value."""
        cat  = int(fields.get("CAT", 1))
        col  = str(fields.get("COL", ""))
        val  = fields.get("VAL")

        if val is not None:
            self.srv.stats.set_stat(self.user.uid, cat, col, val)
            self.user.send(f"+STAT CAT={cat} COL={col} VAL={val}\n")
        else:
            v = self.srv.stats.get_stat(self.user.uid, cat, col)
            self.user.send(f"+STAT CAT={cat} COL={col} VAL={v}\n")

    def _cmd_rank(self, fields):
        entry = self.srv.ranking.get(self.user.uid)
        if not entry:
            entry = self.srv.ranking.get_or_create(self.user.uid, self.user.name)
        pos = self.srv.ranking.get_user_rank(self.user.uid)
        self.user.send(encode_message("RANK",
                                      UID=self.user.uid,
                                      NAME=self.user.name,
                                      SCORE=round(entry.score, 2),
                                      WINS=entry.wins,
                                      LOSSES=entry.losses,
                                      GAMES=entry.games,
                                      POSITION=pos))

    def _cmd_leaderboard(self, fields):
        limit  = int(fields.get("LIMIT", 20))
        board  = self.srv.ranking.get_leaderboard(limit=limit)
        for entry in board:
            self.user.send(encode_message("LBOARD",
                                          POS=entry["position"],
                                          NAME=entry["name"],
                                          SCORE=round(entry["score"], 2),
                                          WINS=entry["wins"],
                                          GAMES=entry["games"]))
        self.user.send(f"+LEADERBOARD COUNT={len(board)}\n")

    def _cmd_server_stat(self, fields):
        """Return master server status. Matches <master usersInLobby=... />"""
        counts = self.srv.users.count()
        gstats = self.srv.games.stats()
        users_lobby_display = counts["lobby"] + counts["rooms"]
        self.user.send(encode_master_stat(
            users_lobby    = users_lobby_display,
            users_rooms    = counts["rooms"],
            users_games    = counts["games"],
            games_progress = gstats["active"],
            games_created  = gstats["created"],
            games_completed= gstats["completed"],
            rooms          = self.srv.rooms.count(),
            sync           = 0,
        ))

    def _cmd_user_set(self, fields):
        """USERSET — update own user fields."""
        allowed = {"LEVEL", "MEDALS", "RGB", "AUX", "FLAGS"}
        for k, v in fields.items():
            if k in allowed:
                setattr(self.user, k.lower(), v)
        self.user.send(encode_user_record(self.user.to_dict()))

    # ------------------------------------------------------------------ #
    # Broadcast helpers                                                    #
    # ------------------------------------------------------------------ #

    def _broadcast_room(self, room_id: int, msg: str, exclude: int = None):
        room = self.srv.rooms.get(room_id)
        if not room:
            return
        for uid in room.members:
            if uid == exclude:
                continue
            u = self.srv.users.get(uid)
            if u:
                u.send(msg)

    def _broadcast_game(self, game_id: int, msg: str, exclude: int = None):
        game = self.srv.games.get(game_id)
        if not game:
            return
        for uid in game.participants:
            if uid == exclude:
                continue
            u = self.srv.users.get(uid)
            if u:
                u.send(msg)

    # ------------------------------------------------------------------ #
    # Disconnect                                                           #
    # ------------------------------------------------------------------ #

    def _on_disconnect(self):
        uid = self.user.uid
        with ClientHandler._handlers_lock:
            ClientHandler._handlers.discard(self)
        active_game = self.srv.games.get(self.user.game) if self.user.game else None
        preserve_detached = self._preserve_on_peer_close(active_game)
        if preserve_detached:
            self.user.connected = False
            self.user.race_detached_at = time.time()
            try:
                self.user.conn.close()
            except Exception:
                pass
            self.srv.request_master_stat_refresh()
            log.info(
                "LOGOUT[handler]: uid=%d reason=%s preserved=detached game=%d state=%s PERS=%s GAMEREPT=%d EXPIRE=%d",
                uid,
                self._disconnect_reason,
                int(getattr(active_game, "id", 0) or 0),
                str(getattr(active_game, "state", "") or "-"),
                self.user.pers,
                self.user.play,
                int(time.time() - self.user.login_time),
            )
            return
        # Clean up room/game memberships
        if self.user.room:
            self._broadcast_room(self.user.room,
                                 encode_message("USERLEAVE",
                                                ROOM=self.user.room,
                                                NAME=self.user.name),
                                 exclude=uid)
            self.srv.rooms.leave(self.user.room, uid)
        if self.user.game:
            game = self.srv.games.get(self.user.game)
            game_after, removed = self.srv.games.leave(self.user.game, uid)
            self.user.game = 0
            self._on_game_departure(game or game_after, departed_uid=int(uid), removed=removed)

        self.srv.users.remove(uid)
        self.srv.request_master_stat_refresh()
        try:
            self.user.conn.close()
        except Exception:
            pass
        log.info("LOGOUT[handler]: uid=%d reason=%s PERS=%s GAMEREPT=%d EXPIRE=%d",
                 uid, self._disconnect_reason,
                 self.user.pers, self.user.play,
                 int(time.time() - self.user.login_time))
