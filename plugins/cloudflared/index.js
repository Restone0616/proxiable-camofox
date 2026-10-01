/**
 * cloudflared plugin for camofox-browser.
 *
 * Publishes the local camofox HTTP server through a Cloudflare Tunnel, so the
 * server can be reached without opening an inbound port on the host.
 *
 * The tunnel starts only when a token is present in the environment. With no
 * token the server boots exactly as it would without this plugin: the status
 * endpoint is registered, a line is logged saying the tunnel is off, and nothing
 * is spawned.
 *
 * Configuration (environment only -- the token is a credential and
 * camofox.config.json is a committed file):
 *   TUNNEL_TOKEN=...             Cloudflare Zero Trust tunnel token; enables the tunnel
 *   CLOUDFLARED_TOKEN=...        Accepted alias for TUNNEL_TOKEN
 *   CLOUDFLARED_BIN=...          cloudflared binary to run (default: cloudflared on PATH)
 *   CLOUDFLARED_MAX_RESTARTS=0   Restart budget after a crash (0 = unlimited)
 *
 * cloudflared's own TUNNEL_* variables are forwarded to the child untouched, so
 * TUNNEL_REGION, TUNNEL_TRANSPORT_PROTOCOL, TUNNEL_METRICS,
 * TUNNEL_EDGE_IP_VERSION and friends work as documented by Cloudflare.
 *
 * Ingress: a token-run tunnel takes its routing from the Cloudflare dashboard,
 * not from this host. Point the public hostname's service at
 * http://localhost:<camofox port>. That port is logged when the tunnel starts
 * and reported by GET /cloudflared/status -- it is read from the listening
 * server rather than from config, so it is correct even when CAMOFOX_PORT=0.
 *
 * Registers:
 *   GET /cloudflared/status -- tunnel state, local port, restart count
 *
 * Events emitted:
 *   cloudflared:started   { pid, localPort }
 *   cloudflared:stopped   { code, signal }
 */

import { resolveCloudflaredConfig, startTunnel } from './cloudflared-launcher.js';

export async function register(app, ctx, pluginConfig = {}) {
  const { events, log } = ctx;
  const settings = ctx.plugin?.settings || pluginConfig;
  const config = resolveCloudflaredConfig(settings);

  let tunnel = null;

  // Registered even when the tunnel is off. An operator who forgot the token
  // gets a straight answer from this endpoint instead of a 404 that looks like
  // the plugin failed to load. The token itself is never reported.
  app.get('/cloudflared/status', (_req, res) => {
    if (!config.enabled) {
      return res.json({
        enabled: false,
        running: false,
        reason: 'no tunnel token configured (set TUNNEL_TOKEN)',
      });
    }
    if (!tunnel) {
      return res.json({
        enabled: true,
        running: false,
        tokenSource: config.tokenSource,
        reason: 'waiting for the server to finish binding its port',
      });
    }
    res.json({ enabled: true, tokenSource: config.tokenSource, ...tunnel.status() });
  });

  if (!config.enabled) {
    log('info', 'cloudflared plugin: no tunnel token configured, starting without a tunnel (set TUNNEL_TOKEN to enable)');
    return;
  }

  // Started from server:started rather than at registration time so the tunnel
  // targets the port the server actually bound.
  events.on('server:started', ({ port }) => {
    if (tunnel) return;
    tunnel = startTunnel({
      binary: config.binary,
      token: config.token,
      localPort: port,
      maxRestarts: config.maxRestarts,
      log,
      events,
      // Test seam: lets the plugin's wiring be exercised without spawning a real
      // cloudflared. Undefined in production, where the launcher uses child_process.
      ...(ctx.__spawnFn ? { spawnFn: ctx.__spawnFn } : {}),
    });
  });

  events.on('server:shutdown', async () => {
    if (!tunnel) return;
    log('info', 'stopping cloudflared tunnel on shutdown');
    await tunnel.stop();
  });

  log('info', 'cloudflared plugin enabled', {
    tokenSource: config.tokenSource,
    binary: config.binary,
    maxRestarts: config.maxRestarts || 'unlimited',
  });
}
