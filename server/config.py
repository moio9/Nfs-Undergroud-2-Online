"""
config.py — Server configuration loader.
Matches all config keys found in server.dll.
"""

import os
import logging

log = logging.getLogger("config")

DEFAULTS = {
    "INCLUDE":                "",
    "CONFIG_INCLUDE":         "",

    # Network - simplified online-server schema.
    # These keys are translated to the explicit listen/public keys after load.
    "PUBLIC_HOST":            "",
    "LISTEN_HOST":            "",
    "BOOTSTRAP_ENDPOINT":     "",
    "LOBBY_ENDPOINT":         "",
    "CONTROL_ENDPOINT":       "",
    "CONTROL_ALIAS_ENDPOINT": "",
    "RACE_ENDPOINT":          "",
    "BOOTSTRAP_LISTEN":       "",
    "LOBBY_LISTEN":           "",
    "CONTROL_LISTEN":         "",
    "CONTROL_ALIAS_LISTEN":   "",
    "RACE_LISTEN":            "",
    "BOOTSTRAP_PORT":         0,
    "LOBBY_PORT":             0,
    "RACE_PORT":              0,
    "AUTH_VERIFY":            0,
    "AUTH_MODE":              "",
    "AUTH_ALLOW_CREATE":      0,
    "AUTH_ACCOUNTS_FILE":     "",
    "AUTH_LEGACY_MASKS":      "",
    "AUTH_REQUIRED_FIELDS":   "",
    "AUTH_REQUIRE_TOS":       0,
    "AUTH_REQUIRE_SHARE":     0,
    "AUTH_FORCE_REJECT_TTL":  300,
    "AUTH_REJECT_REPEAT":     0,
    "AUTH_REJECT_INTERVAL":   0.0,
    "AUTH_REJECT_CLOSE_DELAY": 0.0,
    "PERSONA_MAX_PERSONAS":   0,
    "PERSONA_RESERVED_NAMES": "",
    "PERSONA_FORBIDDEN_WORDS": "",
    "PERSONA_BLACKLIST_FILE": "",
    "PERSONA_BLACKLIST_CODE": "",
    "PERSONA_BLACKLIST_CPER_CODE": "",
    "PERSONA_BLACKLIST_PERS_CODE": "",
    "SOCIAL_FILE":            "",
    "SOCIAL_ENABLED":         0,
    "SOCIAL_SHOW_ALL_ONLINE": 0,
    "SOCIAL_OUTGOING_REQUEST_ATTR": "",
    "ADMIN_BANS_FILE":        "",
    "RANK_FILE":              "",
    "STATS_FILE":             "",
    "GAME_REPORTS_FILE":      "",
    "CONTROL_GATEWAY_ADDR":   "",
    "RACE_GAME_PORT":         0,
    "RACE_LOCAL_PORT":        0,
    "RACE_LOCAL_PORT_SPAN":   0,
    "RACE_DETACHED_GRACE":    0.0,
    "RACE_DETACHED_ACTIVE_GRACE": 0.0,

    # Network — explicit service schema (listen/public)
    "LOBBY_REDIRECT_ENABLE":  0,
    "LOBBY_REDIRECT_LISTEN_HOST": "",
    "LOBBY_REDIRECT_LISTEN_PORT": 0,
    "LOBBY_LEGACY_LISTEN_HOST": "",
    "LOBBY_LEGACY_LISTEN_PORT": 0,
    "LOBBY_LISTEN_HOST":      "",
    "LOBBY_LISTEN_PORT":      0,
    "LOBBY_EXTRA_LISTEN_PORTS": "",
    "LOBBY_PUBLIC_HOST":      "",
    "LOBBY_PUBLIC_PORT":      0,
    "CONTROL_LISTEN_HOST":    "",
    "CONTROL_LISTEN_PORT":    0,
    "CONTROL_PUBLIC_HOST":    "",
    "CONTROL_PUBLIC_PORT":    0,
    "CONTROL_ALIAS_LISTEN_HOST": "",
    "CONTROL_ALIAS_LISTEN_PORT": 0,
    "CONTROL_ALIAS_PUBLIC_HOST": "",
    "CONTROL_ALIAS_PUBLIC_PORT": 0,
    "RACE_LISTEN_HOST":       "",
    "RACE_LISTEN_PORT":       0,
    "RACE_PUBLIC_HOST":       "",
    "RACE_PUBLIC_PORT":       0,
    "INCLUDE_RELAY_FIELDS": 0,
    "LAN_LOOPBACK_ALIAS_PEERS": 0,
    "LAN_GSEA_CUST_FILTERS": 1,
    "RACE_VIRTUAL_PEER_MODE": "off",
    "RACE_VIRTUAL_PEER_SUBNET": "100.64.0.0/24",
    "UDP_RELAY_PRUNE_ROOM_ENDPOINTS": 1,
    "UDP_RELAY_ACK_CMD5_UNRAW": 1,
    "UDP_RELAY_SPOOF_PEER_WINDOW": 6.0,
    "UDP_RELAY_RESET_ON_GAME_START": 1,
    "UDP_RELAY_VERBOSE":      0,
    "UDP_DEBUG":              0,
    "UDP_GAME_PORT":          3658,
    "UDP_LOCAL_PORT":         40001,
    "UDP_LOCAL_PORT_SPAN":    8,
    "UDP_SAME_HOST_RAW_ECHO_LIMIT": 0,

    # Network — legacy/backward-compat keys
    "HOST":                   "0.0.0.0",
    "ADVERTISED_HOST":        "",
    "ADVERTISED_PORT":        0,
    "ADVERTISED_GAME_HOST":   "",
    "ADVERTISED_GAME_PORT":   0,
    "ADVERTISED_GAME_TCP_PORT": 0,
    "ADVERTISED_GAME_ENDPOINTS_FILE": "",
    "GAME_RELAY_PORT":        0,
    "PORT":                   9900,
    "CONTROL_PORT":           20923,
    "CONTROL_ALIAS_PORT":     13505,
    "CONTROL_EPGT_ADDR":      "",
    "CONTROL_RNOT_ENABLE":    1,
    "CONTROL_RNOT_SELF_ENABLE": 0,
    "CONTROL_GENERIC_ACK_ENABLE": 1,
    "CONTROL_SOCIAL_ENABLE":  1,
    "CONTROL_SOCIAL_ALL_ONLINE_ENABLE": 1,
    "CONTROL_SOCIAL_FILE":    "data/social_relations.json",
    "CONTROL_SOCIAL_OUTGOING_REQUEST_ATTR": "P",
    "MASTER_HOST":            "",
    "MASTER_PORT":            11200,
    "LOBBY_TCP_HOST":         "",
    "LOBBY_TCP_PORT":         0,
    "RACE_UDP_HOST":          "",
    "RACE_UDP_PORT":          0,

    # Limits
    "SERVER_MAX_PLAYERS":     256,
    "SERVER_CONN_RATE_LIMIT":  20,
    "SERVER_CONN_RATE_WINDOW": 10.0,
    "SERVER_CONN_RATE_BLOCK":  5.0,
    "USERS":                  256,
    "ROOMS":                  32,
    "ROOMMAX":                64,
    "GAMES":                  128,
    "GAMELIM":                1000,
    "STATLIM":                10000,
    "RANKLIM":                10000,
    "USER_ITERATE_QUEUE_SIZE": 64,

    # Timeouts (seconds)
    "GAMETIMEOUT":            3600,
    "GAME_EXPIRE_TIME":       300,
    "QUICKMATCH_TIMEOUT":     30,
    "SERVER_STAT_REFRESH":    60,
    "LAN_TERM_SST_DELAY":     2.7,
    "LAN_JOIN_MGM_DELAY":     0.015,
    "LAN_JOIN_NOTIFY_MGM":    0,
    "LAN_FRAME_TRACE":        1,
    "LAN_JOIN_COUNTDOWN_ENABLE": 0,
    "LAN_JOIN_COUNTDOWN_DELAY": 10.7,
    "LAN_READY_NOTIFY_PEERS": 1,
    "LAN_READY_COUNTDOWN_ENABLE": 0,
    "LAN_READY_COUNTDOWN_DELAY": 3.0,
    "LAN_READY_UNSET_GRACE": 4.0,
    "LAN_INVITE_PENDING_SECONDS": 90.0,
    "LAN_DETACH_ON_PEER_CLOSE":  1,
    "LAN_DETACHED_GRACE":        20.0,
    "LAN_REATTACH_OPEN_GAMES":   0,
    "BOOTSTRAP_AUTOSTART":     0,
    "LAN_NEWS_MODE":          "captured",
    "LAN_NEWS_HOST":          "",
    "LAN_NEWS_BUDDY_PORT":    0,
    "LAN_NEWS_HTTP_PORT":     0,
    "LAN_TOS_FILE":           "tos",
    "LAN_NEWS_FILE":          "news",
    "LAN_PRELOGIN_BURST_AFTER_NEWS": 1,
    "LAN_NEWS_PUSH_AFTER_AUTH": 0,
    "LAN_NEWS_PUSH_DELAY":    0.75,
    "LAN_NEWS_AUTOPUSH_AUTH":  0,
    "LAN_AUTH_AUTOPUSH":       0,
    "LAN_AUTH_TOS":            3,
    "LAN_ATH_TOS":             1,
    "LAN_AUTH_VERIFY":         0,
    "LAN_AUTH_MODE":           "password",
    "LAN_AUTH_CAPTURE":        0,
    "LAN_AUTH_CAPTURE_FILE":   "data/auth_captures.jsonl",
    "LAN_AUTH_AUTO_ENROLL":    0,
    "LAN_AUTH_MIGRATE_PLAINTEXT": 1,
    "LAN_AUTH_SECURE_STORE":   1,
    "LAN_AUTH_FAIL_LIMIT":     5,
    "LAN_AUTH_FAIL_WINDOW":    60,
    "LAN_AUTH_LOCKOUT_SECONDS": 120,
    "LAN_AUTH_ALLOW_CREATE":   0,
    "LAN_AUTH_ACCOUNTS_FILE":  "data/auth_accounts.json",
    "LAN_AUTH_LEGACY_MASKS":   "",
    "LAN_AUTH_REQUIRED_FIELDS": "",
    "LAN_AUTH_REQUIRE_TOS":    0,
    "LAN_AUTH_REQUIRE_SHARE":  0,
    "LAN_AUTH_FORCE_REJECT_TTL": 300,
    "LAN_AUTH_REJECT_REPEAT":  4,
    "LAN_AUTH_REJECT_INTERVAL": 0.25,
    "LAN_AUTH_REJECT_CLOSE_DELAY": 1.10,
    "LAN_AUTH_EXTRA_PERSONAS":  "",
    "LAN_PERSONA_UNIQUE":      1,
    "LAN_PERSONA_MAX_PERSONAS": 0,
    "LAN_PERSONA_RESERVED_NAMES": "",
    "LAN_PERSONA_FORBIDDEN_WORDS": "",
    "LAN_PERSONA_BLACKLIST_FILE": "",
    "LAN_PERSONA_BLACKLIST_CODE": "invp",
    "LAN_PERSONA_BLACKLIST_CPER_CODE": "",
    "LAN_PERSONA_BLACKLIST_PERS_CODE": "",
    "LAN_DIR_SESS":            0,
    "LAN_DIR_MASK":            "",
    "RANK_MINIMUM_TIME":      60,
    "RANK_REPORT_TIME":       300,
    "RANK_SAVE_TIME":         600,

    # Files
    "GAMEFILE":               "data/game_reports.dat",
    "STATSFILE":              "data/stats.dat",
    "RANKFILE":               "data/rankings.dat",
    "GAMELOG":                "logs/game.log",
    "STATLOG":                "logs/stat.log",
    "RANKLOG":                "logs/rank.log",
    "ADMIN_BANFILE":          "data/admin_bans.json",

    # Game config
    "GAME":                   1,
    "LOBBY_IDENT":            1,
    "LOBBY_MATCH":            0,
    "AUTOROOM":               0,
    "USERFLAGS":              0,
    "DEFAULT_USER_COLOR":     0xFFFFFF,
    "LAN_USER_CL":            0,
    "LAN_USER_RGB":           0,
    "LAN_SPECIAL_PERSONAS":   "",
    "LAN_SPECIAL_USER_CL":    511,
    "LAN_SPECIAL_USER_RGB":   511,
    "LAN_SPECIAL_ONLN_FLAG":  "G",
    "LAN_ONLN_GAME_FLAG":     "U",

    # Ranking
    "RANK_AUTHENT":           1,
    "RANK_EVALUATE_GAME":     1,
    "RANK_OUTPUT_RAW":        0,
    "RANKINGS":               "",
    "UNRANKALL_FIELDS":       "",
    "TRUST_MATCH":            0,
    "OVERRIDE_MATCH":         0,

    # HTTP reporting
    "ALERTS_DCR_URL":         "",
    "HTTP_HOST":              "",
    "HTTP_PORT":              80,

    # Anti-cheat
    "ASYNC":                  0,

    # Master mode
    "MASTER":                 "",
    "SYNC":                   0,

    # Auto-balance
    "AUTOENABLE":             0,
    "AUTOTHRESHOLD":          80,
}


class Config:
    def __init__(self):
        self._data = dict(DEFAULTS)
        self._specified = set()

    def _set_if_unspecified(self, key: str, value):
        key = key.upper()
        if key in self._specified:
            return
        self._data[key] = value

    @staticmethod
    def _parse_endpoint(value: str):
        raw = str(value or "").strip()
        if not raw:
            return "", 0
        if raw.startswith("["):
            end = raw.find("]")
            if end > 0 and len(raw) > end + 2 and raw[end + 1] == ":":
                host = raw[1:end].strip()
                port_text = raw[end + 2 :].strip()
            else:
                return "", 0
        else:
            host, sep, port_text = raw.rpartition(":")
            if not sep:
                return "", 0
            host = host.strip()
            port_text = port_text.strip()
        try:
            port = int(port_text, 10)
        except ValueError:
            return "", 0
        if not host or port <= 0:
            return "", 0
        return host, port

    def _apply_endpoint_alias(self, key: str, host_keys, port_keys):
        if key not in self._specified:
            return
        host, port = self._parse_endpoint(self._data.get(key, ""))
        if not host or port <= 0:
            log.warning("Invalid endpoint %s=%r; expected host:port", key, self._data.get(key, ""))
            return
        for host_key in host_keys:
            self._set_if_unspecified(host_key, host)
        for port_key in port_keys:
            self._set_if_unspecified(port_key, port)

    def _apply_simplified_aliases(self):
        public_host = str(self._data.get("PUBLIC_HOST", "") or "").strip()
        listen_host = str(self._data.get("LISTEN_HOST", "") or "").strip()

        if public_host:
            for key in (
                "LOBBY_PUBLIC_HOST",
                "CONTROL_PUBLIC_HOST",
                "CONTROL_ALIAS_PUBLIC_HOST",
                "RACE_PUBLIC_HOST",
                "LAN_NEWS_HOST",
            ):
                self._set_if_unspecified(key, public_host)

        if listen_host:
            for key in (
                "LOBBY_LEGACY_LISTEN_HOST",
                "LOBBY_LISTEN_HOST",
                "CONTROL_LISTEN_HOST",
                "CONTROL_ALIAS_LISTEN_HOST",
                "RACE_LISTEN_HOST",
            ):
                self._set_if_unspecified(key, listen_host)
            self._set_if_unspecified("HOST", listen_host)

        bootstrap_port = int(self._data.get("BOOTSTRAP_PORT", 0) or 0)
        if bootstrap_port > 0:
            self._set_if_unspecified("LOBBY_LEGACY_LISTEN_PORT", bootstrap_port)

        lobby_port = int(self._data.get("LOBBY_PORT", 0) or 0)
        if lobby_port > 0:
            self._set_if_unspecified("LOBBY_LISTEN_PORT", lobby_port)
            self._set_if_unspecified("LOBBY_PUBLIC_PORT", lobby_port)

        race_port = int(self._data.get("RACE_PORT", 0) or 0)
        if race_port > 0:
            self._set_if_unspecified("RACE_LISTEN_PORT", race_port)
            self._set_if_unspecified("RACE_PUBLIC_PORT", race_port)

        self._apply_endpoint_alias(
            "BOOTSTRAP_ENDPOINT",
            (),
            ("LOBBY_LEGACY_LISTEN_PORT",),
        )
        self._apply_endpoint_alias(
            "LOBBY_ENDPOINT",
            ("LOBBY_PUBLIC_HOST",),
            ("LOBBY_LISTEN_PORT", "LOBBY_PUBLIC_PORT"),
        )
        self._apply_endpoint_alias(
            "CONTROL_ENDPOINT",
            ("CONTROL_PUBLIC_HOST", "LAN_NEWS_HOST"),
            ("CONTROL_LISTEN_PORT", "CONTROL_PUBLIC_PORT", "CONTROL_PORT"),
        )
        self._apply_endpoint_alias(
            "CONTROL_ALIAS_ENDPOINT",
            ("CONTROL_ALIAS_PUBLIC_HOST",),
            ("CONTROL_ALIAS_LISTEN_PORT", "CONTROL_ALIAS_PUBLIC_PORT", "CONTROL_ALIAS_PORT"),
        )
        self._apply_endpoint_alias(
            "RACE_ENDPOINT",
            ("RACE_PUBLIC_HOST",),
            ("RACE_LISTEN_PORT", "RACE_PUBLIC_PORT"),
        )
        self._apply_endpoint_alias(
            "BOOTSTRAP_LISTEN",
            ("LOBBY_LEGACY_LISTEN_HOST",),
            ("LOBBY_LEGACY_LISTEN_PORT",),
        )
        self._apply_endpoint_alias(
            "LOBBY_LISTEN",
            ("LOBBY_LISTEN_HOST",),
            ("LOBBY_LISTEN_PORT",),
        )
        self._apply_endpoint_alias(
            "CONTROL_LISTEN",
            ("CONTROL_LISTEN_HOST",),
            ("CONTROL_LISTEN_PORT",),
        )
        self._apply_endpoint_alias(
            "CONTROL_ALIAS_LISTEN",
            ("CONTROL_ALIAS_LISTEN_HOST",),
            ("CONTROL_ALIAS_LISTEN_PORT",),
        )
        self._apply_endpoint_alias(
            "RACE_LISTEN",
            ("RACE_LISTEN_HOST",),
            ("RACE_LISTEN_PORT",),
        )
        simple_aliases = {
            "AUTH_VERIFY": "LAN_AUTH_VERIFY",
            "AUTH_MODE": "LAN_AUTH_MODE",
            "AUTH_ALLOW_CREATE": "LAN_AUTH_ALLOW_CREATE",
            "AUTH_ACCOUNTS_FILE": "LAN_AUTH_ACCOUNTS_FILE",
            "AUTH_LEGACY_MASKS": "LAN_AUTH_LEGACY_MASKS",
            "AUTH_REQUIRED_FIELDS": "LAN_AUTH_REQUIRED_FIELDS",
            "AUTH_REQUIRE_TOS": "LAN_AUTH_REQUIRE_TOS",
            "AUTH_REQUIRE_SHARE": "LAN_AUTH_REQUIRE_SHARE",
            "AUTH_FORCE_REJECT_TTL": "LAN_AUTH_FORCE_REJECT_TTL",
            "AUTH_REJECT_REPEAT": "LAN_AUTH_REJECT_REPEAT",
            "AUTH_REJECT_INTERVAL": "LAN_AUTH_REJECT_INTERVAL",
            "AUTH_REJECT_CLOSE_DELAY": "LAN_AUTH_REJECT_CLOSE_DELAY",
            "PERSONA_MAX_PERSONAS": "LAN_PERSONA_MAX_PERSONAS",
            "PERSONA_RESERVED_NAMES": "LAN_PERSONA_RESERVED_NAMES",
            "PERSONA_FORBIDDEN_WORDS": "LAN_PERSONA_FORBIDDEN_WORDS",
            "PERSONA_BLACKLIST_FILE": "LAN_PERSONA_BLACKLIST_FILE",
            "PERSONA_BLACKLIST_CODE": "LAN_PERSONA_BLACKLIST_CODE",
            "PERSONA_BLACKLIST_CPER_CODE": "LAN_PERSONA_BLACKLIST_CPER_CODE",
            "PERSONA_BLACKLIST_PERS_CODE": "LAN_PERSONA_BLACKLIST_PERS_CODE",
            "SOCIAL_FILE": "CONTROL_SOCIAL_FILE",
            "SOCIAL_ENABLED": "CONTROL_SOCIAL_ENABLE",
            "SOCIAL_SHOW_ALL_ONLINE": "CONTROL_SOCIAL_ALL_ONLINE_ENABLE",
            "SOCIAL_OUTGOING_REQUEST_ATTR": "CONTROL_SOCIAL_OUTGOING_REQUEST_ATTR",
            "ADMIN_BANS_FILE": "ADMIN_BANFILE",
            "RANK_FILE": "RANKFILE",
            "STATS_FILE": "STATSFILE",
            "GAME_REPORTS_FILE": "GAMEFILE",
            "CONTROL_GATEWAY_ADDR": "CONTROL_EPGT_ADDR",
            "RACE_GAME_PORT": "UDP_GAME_PORT",
            "RACE_LOCAL_PORT": "UDP_LOCAL_PORT",
            "RACE_LOCAL_PORT_SPAN": "UDP_LOCAL_PORT_SPAN",
        }
        for src, dst in simple_aliases.items():
            if src in self._specified:
                self._set_if_unspecified(dst, self._data.get(src))

    def _load_file(self, path: str, seen: set[str]) -> bool:
        path = os.path.abspath(path)
        if path in seen:
            log.warning("Skipping recursive config include: %s", path)
            return True
        seen.add(path)

        if not os.path.exists(path):
            log.warning("Config file not found: %s", path)
            return False

        log.info("Loading stats configuration from '%s'", path)
        try:
            with open(path, "r") as f:
                for lineno, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Support KEY=VALUE and KEY VALUE
                    if "=" in line:
                        k, _, v = line.partition("=")
                    else:
                        parts = line.split(None, 1)
                        if len(parts) < 2:
                            continue
                        k, v = parts[0], parts[1]

                    k = k.strip().upper()
                    v = v.strip().strip('"').strip("'")

                    if k in ("INCLUDE", "CONFIG_INCLUDE"):
                        include_path = v
                        if include_path and not os.path.isabs(include_path):
                            include_path = os.path.join(os.path.dirname(path), include_path)
                        if include_path and not self._load_file(include_path, seen):
                            return False
                        continue

                    if k not in self._data:
                        log.warning("%s:%d invalid configuration '%s'", path, lineno, k)
                        continue
                    self._specified.add(k)

                    # Type-preserve
                    orig = self._data[k]
                    try:
                        if isinstance(orig, int):
                            self._data[k] = int(v)
                        elif isinstance(orig, float):
                            self._data[k] = float(v)
                        else:
                            self._data[k] = v
                    except ValueError:
                        self._data[k] = v

            log.info("Loaded stats configuration from '%s'", path)
            return True
        except Exception as e:
            log.error("Loading stats configuration from '%s' failed: %s", path, e)
            return False

    def load(self, path: str) -> bool:
        """
        Load config from file. Format: KEY=VALUE or KEY VALUE per line.
        Matches DLL's 'Loading stats configuration from %s' behavior.
        """
        ok = self._load_file(path, set())
        if ok:
            self._apply_simplified_aliases()
        return ok

    def get(self, key: str, default=None):
        return self._data.get(key.upper(), default)

    def __getitem__(self, key: str):
        return self._data[key.upper()]

    def __setitem__(self, key: str, value):
        self._data[key.upper()] = value

    def dump(self) -> str:
        lines = []
        for k, v in sorted(self._data.items()):
            lines.append(f"{k}={v}")
        return "\n".join(lines)
