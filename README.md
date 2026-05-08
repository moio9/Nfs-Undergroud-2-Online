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
- `5000/udp` - race relay

Game clients also need local `3658/udp` free for race peer traffic. This is not
the server relay port, but it matters during same-machine or same-LAN testing,
especially after a crashed/stale game instance.

By default, the server prints only warnings/errors in the terminal and writes
normal logs to `server/logs/server.log`.

## Public Server

- Server IP: `161.35.110.36`

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

## Release Prep

See `docs/RELEASE.md` for the launch checklist, public-host settings, required
ports, and packaging notes.

## Support

Please help to keep this project alive.

If I cannot raise at least 4 EUR per month, I will not be able to keep my server
online for that month.

- Monero: `46Mk8t9uLY7jnBXnyHMyVARvwk1Y7jcGEQwKLN8GtGGBioncjKLgkEa33jEN2ibgkQjoFZWVwXXwsM3vzAFz4RzV7psLow6`
- Bitcoin: `bc1qgxp74eza7jaf4fdw5cl3sanqvnh0cjmz0w9scz`
- Ethereum: `0xa024a505Ec24c7eA163985eC89D56e614B9AdAae`
- PayPal: https://paypal.me/moioyoyo

## Contact

- Odysee: https://odysee.com/@moio.yoyo:3
- Steam: https://steamcommunity.com/profiles/76561198169326632
- Discord: `Puya#0957`
- itch: https://moio9.itch.io/
