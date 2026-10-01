# cloudflared Plugin — Agent Guide

Publishes the local camofox HTTP server through a Cloudflare Tunnel, so it can be reached without opening an inbound port.

## Activation

Starts a tunnel **only when a token is present in the environment**. With no token the server boots normally — the status endpoint still answers, nothing is spawned. The token is read from the environment only, never from `camofox.config.json` (that file is committed; the token is a credential).

- `TUNNEL_TOKEN` — Cloudflare Zero Trust tunnel token (enables the tunnel)
- `CLOUDFLARED_TOKEN` — accepted alias for `TUNNEL_TOKEN`
- `CLOUDFLARED_BIN` — binary to run (default: `cloudflared` on PATH)
- `CLOUDFLARED_MAX_RESTARTS` — restart budget after a crash (`0` = unlimited, the default)

cloudflared's own `TUNNEL_*` variables (`TUNNEL_REGION`, `TUNNEL_TRANSPORT_PROTOCOL`, `TUNNEL_METRICS`, `TUNNEL_EDGE_IP_VERSION`, …) are forwarded to the child untouched.

## Endpoint

- `GET /cloudflared/status` — tunnel state, local port, restart count (no auth; never returns the token)

## Ingress

A token-run tunnel takes its routing from the Cloudflare dashboard, not from this host. Point the public hostname's **Service** at `http://localhost:<camofox port>`. The port is logged on start and reported by `/cloudflared/status`; it is read from the listening server, so it is correct even with `CAMOFOX_PORT=0`.

## Key Files

- `index.js` — route handler + lifecycle wiring only (no `child_process`, no `process.env` reads)
- `cloudflared-launcher.js` — process supervision, restart/backoff, config resolution from env (`child_process` isolated here via `spawn.js`)
- `spawn.js` — re-exports `child_process.spawn` (keeps the module name out of handler files, matching the VNC/YouTube convention)
- `post-install.sh` — downloads a pinned `cloudflared` binary and verifies its SHA256 (per architecture)
- `cloudflared-launcher.test.js` / `post-install.test.js` — unit tests

## Code Separation

`child_process` lives in `spawn.js`, env var reads and subprocess management in `cloudflared-launcher.js`, route handlers in `index.js` — separate files per project conventions.

## Supervision

The tunnel is a side channel, not a dependency. If cloudflared exits it is restarted with exponential backoff (1s → 60s cap); the backoff resets after a run that stayed up ≥60s. camofox keeps serving regardless. On `server:shutdown` the child gets SIGTERM, then SIGKILL after a grace window.

## Security

- The token travels in the child's environment, never in argv (`ps` would expose argv).
- Only cloudflared's own `TUNNEL_*` knobs are forwarded to the child; `PROXY_PASSWORD`, API keys, and other host secrets are withheld — the tunnel is the one process here that talks to the public internet.
- A tunnel exposes this server to the internet. Keep `CAMOFOX_API_KEY`/access controls set; the tunnel does not add auth of its own (use Cloudflare Access for that).

## Updating the pinned binary

`post-install.sh` pins `CLOUDFLARED_VERSION` and a SHA256 per architecture. To bump: pick a release from `cloudflare/cloudflared`, copy the `cloudflared-linux-amd64` / `cloudflared-linux-arm64` checksums from its release notes into `default_sha`, and update the version. The pinning test asserts both checksums are present.
