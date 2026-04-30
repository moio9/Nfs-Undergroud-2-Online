# Configuration

This release uses two main config files:

- `client/online/configs/ONLINE.cfg` - copied next to `SPEED2.EXE`.
- `server/server.cfg` - used when starting the Python server.

## Client: ONLINE.cfg

Use `server_host` to point the game to your server. Per-service hosts are optional;
if omitted, they use `server_host`.

For same-machine testing:

```ini
server_host = 127.0.0.1
```

For remote hosting, set it to the server IP or DNS name:

```ini
server_host = 203.0.113.10
```

Default ports:

- `bootstrap_port = 20921`
- `lobby_port = 20922`
- `race_port = 5000`
- `control_port = 20923`
- `control_alias_port = 13505`
- `lan_port = 20922`

LAN and Online intentionally share `20922` in the default release setup.
The game client also uses local UDP `3658` for race peer traffic. This is
separate from `race_port`, which is the relay endpoint.

Optional per-service host keys:

- `bootstrap_host`
- `lobby_host`
- `race_host`
- `control_host`
- `control_alias_host`
- `lan_host`

If a per-service host is omitted, it falls back to `server_host`. If `server_host` is
also omitted, the built-in default host is used.

Ports do not inherit from a main port. If a port is omitted, its built-in default is
used.

Server-advertised endpoints can override configured endpoints after the client
connects, when the server sends endpoint fields for that service.

Race UDP note: when testing the server and clients on the same machine or on the
same LAN, keep the client `race_port`, server `RACE_ENDPOINT` port, and server
`RACE_LISTEN` port the same. The client uses the server-advertised race port, so
if `RACE_ENDPOINT` advertises one UDP port while `RACE_LISTEN` opens another, the
client will send race packets to a port where the server is not listening.

Also keep UDP `3658` free on each client machine before starting the game,
especially during local testing with multiple clients. A stale game process or
another tool holding `3658/udp` can prevent the race UDP socket from behaving
normally even when the relay port is configured correctly.

## Server: server.cfg

Public endpoints are what the server advertises to clients:

```ini
SERVER_MAX_PLAYERS=256
SERVER_MAX_CONNECTIONS=64
SERVER_CONN_RATE_LIMIT=20
SERVER_CONN_RATE_WINDOW=10
SERVER_CONN_RATE_BLOCK=5
SERVER_TCP_TIMEOUT=60
SERVER_MAX_BUFFER_BYTES=131072
BOOTSTRAP_ENDPOINT=127.0.0.1:20921
LOBBY_ENDPOINT=127.0.0.1:20922
RACE_ENDPOINT=127.0.0.1:5000
UDP_GAME_PORT=3658
```

`SERVER_MAX_PLAYERS` caps simultaneous connected players. New login/auth
attempts are rejected once the limit is reached.

`SERVER_CONN_RATE_LIMIT` caps new TCP lobby/bootstrap connections per source IP
inside `SERVER_CONN_RATE_WINDOW` seconds. When the limit is exceeded, new
connections from that IP are dropped for `SERVER_CONN_RATE_BLOCK` seconds. Set
`SERVER_CONN_RATE_LIMIT=0` to disable this throttle.

`SERVER_MAX_CONNECTIONS` caps active lobby/bootstrap sockets before login, and
`SERVER_MAX_BUFFER_BYTES` drops clients that keep sending incomplete frames or
lines without letting the parser drain the receive buffer.

Listen endpoints are local sockets opened by the server:

```ini
BOOTSTRAP_LISTEN=0.0.0.0:20921
LOBBY_LISTEN=0.0.0.0:20922
RACE_LISTEN=0.0.0.0:5000
```

For remote hosting, usually change only the public endpoints to your public IP/host.
Keep listen endpoints on `0.0.0.0` unless you need to bind a specific interface.
For same-machine or same-LAN testing, keep `RACE_ENDPOINT` and `RACE_LISTEN` on
the same UDP port.
`UDP_GAME_PORT=3658` is the original game peer UDP port used inside relayed
packets; it is not the relay listen port, but it must be free on client machines.

LAN lobby search can either follow stock `CUSTFLAGS/CUSTMASK` filtering or list
all public games regardless of those filters:

```ini
LOBBY_GSEA_CUST_FILTERS=1
```

Use `1` for stock behavior: `gsea` applies race mode, car/performance class, and
related `CUSTFLAGS` filters. Use `0` to ignore `CUSTFLAGS/CUSTMASK` during
search; private/matched filtering through `SYSFLAGS` still applies.

## Abuse Limits

Control/social sockets use the same connection-rate throttle as lobby sockets,
plus their own active connection and message limits:

```ini
CONTROL_REQUIRE_LOBBY_SESSION=1
CONTROL_TRUST_CLIENT_PERSONA=0
CONTROL_PROFILE_TTL=90.0
CONTROL_MAX_CONNECTIONS=32
CONTROL_PREAUTH_TIMEOUT=20.0
CONTROL_IDLE_TIMEOUT=120.0
CONTROL_HTTP_MAX_BODY=8192
CONTROL_MAX_FRAME_BYTES=65535
```

With `CONTROL_REQUIRE_LOBBY_SESSION=1`, the control persona must match a recent
lobby profile or an active lobby user from the same peer IP. Keep
`CONTROL_TRUST_CLIENT_PERSONA=0` for public servers.

UDP relay state is also bounded:

```ini
UDP_RELAY_MAX_CLIENTS=128
UDP_RELAY_MAX_PENDING_ROOMS=128
UDP_RELAY_PENDING_ROOM_TTL=60.0
```

`RANKLIM` and `STATLIM` are hard caps. Once reached, new ranking/stat identities
are ignored instead of being persisted.

## Logging

The release config keeps the console quiet and writes normal logs to a file:

```ini
DEBUG_MODE=0
LOG_LEVEL=INFO
LOG_CONSOLE_LEVEL=WARNING
LOG_FILE=logs/server.log
LOG_FILE_LEVEL=INFO
LOBBY_FRAME_TRACE=0
UDP_RELAY_VERBOSE=0
UDP_DEBUG=off
```

`DEBUG_MODE` is general server debug; it writes DEBUG logs to `LOG_FILE` while
the console still follows `LOG_CONSOLE_LEVEL`. `UDP_RELAY_VERBOSE`/`UDP_DEBUG`
are only for race relay diagnostics. `LOBBY_FRAME_TRACE=1` is very noisy and
should only be enabled while debugging lobby packet flow.

To disable all logging, use:

```ini
LOG_CONSOLE_LEVEL=OFF
LOG_FILE=
```

At runtime, the admin shell supports:

```text
debug status|on|off
udpdebug status|on|off
```

## Authentication

Account validation is controlled by `AUTH_VERIFY`:

```ini
AUTH_VERIFY=1
AUTH_ALLOW_CREATE=1
```

Use `AUTH_VERIFY=0` for LAN/no-auth mode. Use `AUTH_VERIFY=1` for Online/account
verification mode. Accounts are read from:

```ini
AUTH_ACCOUNTS_FILE=data/auth_accounts.json
```

Use `server/data/auth_accounts.example.json` as the format reference.

Optional stock-auth rejection helpers:

```ini
AUTH_REQUIRED_FIELDS=VERS,SLUS,SKU,LANG
AUTH_REQUIRE_TOS=0
AUTH_REQUIRE_SHARE=0
```

Account records can force stock client auth errors with `auth_code`/`auth_status`
values such as `lock`, `blak`, `tosa`, `shar`, `ikey`, `time`, `over`, `filt`,
or `dber`.

For live client testing from the local admin shell:

```text
authcode blak Alice
authcode tosa *
authcode list
authcode clear
authreject slow
authreject default
personacode cperinvp *
personacode persmaut Alice
personacode codes
```

The override is consumed by the next matching login attempt, so restart or
reconnect the game client after queuing it.

`authreject slow` keeps the auth error visible for about 8 seconds before the
server closes the connection. For a permanent test setup, use:

```ini
AUTH_REJECT_REPEAT=1
AUTH_REJECT_CLOSE_DELAY=8.0
```

Persona test codes are:

```text
cperdupl cperinvp cpernspc persinvp persmaut perspset
```

Normal login usually selects an existing persona, so it sends `pers`. Use
`persinvp`, `persmaut`, or `perspset` for that path. `cperdupl`, `cperinvp`,
and `cpernspc` only apply when the client is creating a new persona and sends
`cper`.

Persona blacklist/reserved-name checks are configurable:

```ini
LAN_PERSONA_RESERVED_NAMES=
LAN_PERSONA_FORBIDDEN_WORDS=
LAN_PERSONA_BLACKLIST_FILE=data/persona_blacklist.txt
LAN_PERSONA_BLACKLIST_CODE=invp
LAN_PERSONA_BLACKLIST_CPER_CODE=
LAN_PERSONA_BLACKLIST_PERS_CODE=pset
```

`LAN_PERSONA_RESERVED_NAMES` matches exact persona names, case-insensitive.
`LAN_PERSONA_FORBIDDEN_WORDS` matches substrings, useful for profanity fragments.
`LAN_PERSONA_BLACKLIST_FILE` is the recommended place for the real list; each
non-comment line is exact by default, or can use `exact:name` / `contains:word`.

Example `data/persona_blacklist.txt`:

```text
exact:admin
exact:administrator
exact:moderator
exact:server
exact:system
contains:badword
```

The default create-persona reject code is `invp`. Normal login uses the
select-persona path, so `LAN_PERSONA_BLACKLIST_PERS_CODE=pset` maps blacklist
hits to `perspset` instead of `persinvp`.

## Runtime Data

These files are safe release placeholders:

- `server/data/auth_accounts.json`
- `server/data/admin_bans.json`
- `server/data/social_relations.json`
- `server/data/rankings.dat`
- `server/data/stats.dat`
- `server/data/game_reports.dat`
