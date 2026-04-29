# NFSU2 Online LAN Release

Standalone release workspace for the `online` client and the Python server.

## Layout

- `client/online` - client source, build script, config, and prebuilt ASI.
- `server` - Python Online/LAN server.
- `server/data` - clean runtime data files for release.
- `docs` - release documentation.

## Start The Server

```sh
cd server
python server.py server.cfg
```

The default config listens on:

- `20921/tcp` - legacy bootstrap for the client
- `20922/tcp` - lobby TCP, used by both Online and LAN injection
- `20923/tcp` - control
- `13505/tcp` - control alias
- `2000/udp` - race relay

Game clients also need local `3658/udp` free for race peer traffic. This is not
the server relay port, but it matters during same-machine or same-LAN testing,
especially after a crashed/stale game instance.

## Install The Client

1. Copy `client/online/dist/online.asi` into the game's `scripts` folder.
2. Copy `client/online/configs/ONLINE.cfg` next to the game executable.
3. Set `relay_host` and `lan_host` to your server IP/host.

By default, LAN injection uses the same lobby port as Online:

```ini
relay_tcp_port = 20922
lan_override_host = on
lan_port = 20922
lan_provider_seed = on
```

## Build The Client

```sh
cd client/online
./build.sh
```

Requires `i686-w64-mingw32-g++`.

## Configuration

See `docs/CONFIG.md`.
