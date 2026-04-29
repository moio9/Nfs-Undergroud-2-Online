# online

Standalone build of the online plugin.

## Layout

- `src/online.cpp` - client source
- `configs/ONLINE.cfg` - local test config
- `dist/` - build output
- `build.sh` - compiles `src/online.cpp` into `dist/online.asi`

The config supports endpoint overrides and logging.

Primary host options:

- `server_host`
- `bootstrap_host`
- `lobby_host`
- `race_host`
- `control_host`
- `control_alias_host`
- `lan_host`

Primary port options:

- `bootstrap_port`
- `lobby_port`
- `race_port`
- `control_port`
- `control_alias_port`
- `lan_port`

LAN and logging options:

- `lan_override_host`
- `lan_provider_seed`
- `debug`

LAN through online:

```ini
lan_override_host = on
server_host = 203.0.113.10
lan_port = 20922
lan_provider_seed = on
```

With `lan_override_host=on`, the game's original LAN TCP connection is redirected to
the configured LAN endpoint. With `lan_provider_seed=on`, the configured server is
injected directly into the LAN server list, so the browser does not depend on UDP
discovery.

If a per-service host is omitted, it falls back to `server_host`. If `server_host` is
also omitted, the built-in default is used. Ports do not inherit from a main port;
omitted ports use their built-in defaults.

For same-machine or same-LAN race testing, keep `race_port` aligned with the
server's `RACE_ENDPOINT` and `RACE_LISTEN` UDP port. The client can consume the
server-advertised race endpoint, but the advertised port still has to be a port
where the server is actually listening.

The game also uses local UDP `3658` for race peer traffic. Keep `3658/udp` free
on each client machine, especially when testing multiple clients locally. This is
separate from `race_port`, which points at the relay.

This build focuses on endpoint redirection, LAN server injection, and logging.

## Build

```sh
./build.sh
```

The build produces one file:

- `dist/online.asi`
