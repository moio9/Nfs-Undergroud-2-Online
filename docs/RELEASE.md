# Release Checklist

Use this checklist before packaging or hosting a public build.

## 1. Choose The Public Host

Pick the DNS name or public IP that players will use, then update:

- `server/server.cfg`
- `client/online/configs/ONLINE.cfg`

In `server/server.cfg`, keep listen addresses on `0.0.0.0` for normal hosting
and change only the advertised endpoints:

```ini
BOOTSTRAP_ENDPOINT=your.host.name:20921
LOBBY_ENDPOINT=your.host.name:20922
CONTROL_ENDPOINT=your.host.name:20923
CONTROL_ALIAS_ENDPOINT=your.host.name:13505
RACE_ENDPOINT=your.host.name:5000
```

In `client/online/configs/ONLINE.cfg`, set:

```ini
server_host = your.host.name
debug = off
```

## 2. Open Required Ports

Open these inbound ports on the server firewall/router:

- `20921/tcp` - bootstrap
- `20922/tcp` - lobby and LAN injection
- `20923/tcp` - control/social
- `13505/tcp` - control alias
- `5000/udp` - race relay

Client machines also need local `3658/udp` free before starting the game.

## 3. Select Auth Mode

For a public account-based launch:

```ini
AUTH_VERIFY=1
AUTH_ALLOW_CREATE=1
AUTH_ACCOUNTS_FILE=data/auth_accounts.json
```

For a LAN or open test launch:

```ini
AUTH_VERIFY=0
AUTH_ALLOW_CREATE=1
```

Keep `CONTROL_REQUIRE_LOBBY_SESSION=1` and `CONTROL_TRUST_CLIENT_PERSONA=0` for
Internet-facing servers.

## 4. Verify Release Settings

Before packaging, verify these are set:

- `DEBUG_MODE=0`
- `LOG_CONSOLE_LEVEL=WARNING`
- `LOG_FILE=logs/server.log`
- `LOBBY_FRAME_TRACE=0`
- `UDP_RELAY_VERBOSE=0`
- `UDP_DEBUG=off`
- `client/online/configs/ONLINE.cfg`: `debug = off`

Adjust capacity for launch size:

```ini
SERVER_MAX_PLAYERS=10
SERVER_MAX_CONNECTIONS=64
UDP_RELAY_MAX_CLIENTS=128
```

Increase `SERVER_MAX_PLAYERS` only after the host has been tested under load.

## 5. Rebuild And Test

Run the server integration test:

```sh
PYTHONPATH=server python tools/test_client.py
```

Rebuild the client when `client/online/src/online.cpp` changes:

```sh
cd client/online
./build.sh
```

The build output for players is:

- `client/online/dist/online.asi`
- `client/online/configs/ONLINE.cfg`
