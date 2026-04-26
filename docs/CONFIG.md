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
- `race_port = 2000`
- `control_port = 20923`
- `control_alias_port = 13505`
- `lan_port = 20922`

LAN and Online intentionally share `20922` in the default release setup.

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

## Server: server.cfg

Public endpoints are what the server advertises to clients:

```ini
BOOTSTRAP_ENDPOINT=127.0.0.1:20921
LOBBY_ENDPOINT=127.0.0.1:20922
RACE_ENDPOINT=127.0.0.1:2000
```

Listen endpoints are local sockets opened by the server:

```ini
BOOTSTRAP_LISTEN=0.0.0.0:20921
LOBBY_LISTEN=0.0.0.0:20922
RACE_LISTEN=0.0.0.0:2000
```

For remote hosting, usually change only the public endpoints to your public IP/host.
Keep listen endpoints on `0.0.0.0` unless you need to bind a specific interface.

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

## Runtime Data

These files are safe release placeholders:

- `server/data/auth_accounts.json`
- `server/data/admin_bans.json`
- `server/data/social_relations.json`
- `server/data/rankings.dat`
- `server/data/stats.dat`
- `server/data/game_reports.dat`
