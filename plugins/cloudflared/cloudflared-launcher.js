/**
 * cloudflared launcher -- owns all process spawning and env reads.
 * Isolated from route handlers to keep subprocess management separate.
 */

import { spawn } from './spawn.js';

const DEFAULT_BINARY = 'cloudflared';
const RESTART_BASE_DELAY_MS = 1000;
const RESTART_MAX_DELAY_MS = 60000;
// A run that lasts this long counts as healthy, so the next crash starts its
// backoff from the bottom instead of inheriting the penalty from an old one.
const HEALTHY_UPTIME_MS = 60000;
const STOP_GRACE_MS = 5000;

function compactEnv(env) {
  return Object.fromEntries(
    Object.entries(env)
      .filter(([, value]) => value !== undefined && value !== null)
      .map(([key, value]) => [key, String(value)])
  );
}

/**
 * Resolve cloudflared configuration from pluginConfig + env var fallbacks.
 * All process.env reads live here -- callers get a plain config object.
 *
 * The token is deliberately read only from the environment: camofox.config.json
 * is a committed file, and this credential grants inbound access to this host.
 */
export function resolveCloudflaredConfig(pluginConfig = {}, env = process.env) {
  const fromTunnelToken = String(env.TUNNEL_TOKEN || '').trim();
  const fromAlias = String(env.CLOUDFLARED_TOKEN || '').trim();
  const token = fromTunnelToken || fromAlias;
  const tokenSource = fromTunnelToken ? 'TUNNEL_TOKEN' : (fromAlias ? 'CLOUDFLARED_TOKEN' : null);

  const binary = String(env.CLOUDFLARED_BIN || pluginConfig.binary || DEFAULT_BINARY).trim() || DEFAULT_BINARY;

  const rawMax = env.CLOUDFLARED_MAX_RESTARTS ?? pluginConfig.maxRestarts;
  const parsedMax = parseInt(rawMax, 10);
  const maxRestarts = Number.isFinite(parsedMax) && parsedMax >= 0 ? parsedMax : 0; // 0 = unlimited

  return { enabled: token.length > 0, token, tokenSource, binary, maxRestarts };
}

/**
 * The canonical container invocation for a token-run tunnel.
 *
 * Autoupdate is off because a binary that replaces itself inside a container
 * restarts the tunnel out from under the supervisor below -- and the pinned
 * version in post-install.sh is the one whose checksum was verified.
 *
 * The token is not an argument. It travels in the child's environment (see
 * buildTunnelEnv) so it never lands in argv, where `ps` would expose it.
 */
export function buildTunnelArgs() {
  return ['tunnel', '--no-autoupdate', 'run'];
}

/**
 * Build the child environment.
 *
 * cloudflared binds its --token flag to TUNNEL_TOKEN, so passing the credential
 * this way is equivalent to the documented `run --token <t>` form minus the argv
 * exposure.
 *
 * Only cloudflared's own TUNNEL_* knobs are forwarded. The parent environment
 * also holds PROXY_PASSWORD and the API keys, and the tunnel has no use for
 * them -- it is the one process here that talks to the public internet.
 */
export function buildTunnelEnv({ token }, env = process.env) {
  const forwarded = Object.fromEntries(
    Object.entries(env).filter(([key]) => key.startsWith('TUNNEL_') && key !== 'TUNNEL_TOKEN')
  );
  return compactEnv({
    PATH: env.PATH,
    HOME: env.HOME,
    ...forwarded,
    TUNNEL_TOKEN: token,
  });
}

/** Exponential backoff, capped. attempt is 1-based. */
export function restartDelayMs(attempt, { base = RESTART_BASE_DELAY_MS, max = RESTART_MAX_DELAY_MS } = {}) {
  if (attempt <= 1) return base;
  return Math.min(max, base * 2 ** (attempt - 1));
}

/**
 * Start cloudflared and keep it running.
 *
 * The tunnel is a side channel, not a dependency: if it dies, it is restarted
 * with backoff and camofox keeps serving regardless.
 *
 * Returns { status(), stop() }.
 */
export function startTunnel({
  binary = DEFAULT_BINARY,
  token,
  localPort,
  maxRestarts = 0,
  log,
  events,
  spawnFn = spawn,
  setTimeoutFn = setTimeout,
  clearTimeoutFn = clearTimeout,
  now = () => Date.now(),
}) {
  const state = {
    child: null,
    pid: null,
    startedAt: null,
    restarts: 0,
    consecutiveFailures: 0,
    lastExit: null,
    stopping: false,
    exhausted: false,
  };
  let restartTimer = null;

  function handleTermination(code, signal) {
    // Compared against null, not truthiness: a launch whose timestamp is 0 has
    // still launched.
    const ranForMs = state.startedAt !== null ? now() - state.startedAt : 0;
    state.lastExit = { code, signal, ranForMs };
    state.child = null;
    state.pid = null;
    state.startedAt = null;

    events.emit('cloudflared:stopped', { code, signal });

    if (state.stopping) {
      log('info', 'cloudflared stopped', { code, signal });
      return;
    }

    // Only a short-lived run is evidence of a crash loop.
    if (ranForMs >= HEALTHY_UPTIME_MS) state.consecutiveFailures = 0;

    if (maxRestarts > 0 && state.restarts >= maxRestarts) {
      state.exhausted = true;
      log('error', 'cloudflared exited and its restart budget is spent; the tunnel stays down', {
        code,
        signal,
        restarts: state.restarts,
        maxRestarts,
      });
      return;
    }

    state.consecutiveFailures += 1;
    state.restarts += 1;
    const delayMs = restartDelayMs(state.consecutiveFailures);
    log('warn', 'cloudflared exited, restarting', {
      code,
      signal,
      ranForMs,
      delayMs,
      restarts: state.restarts,
    });

    restartTimer = setTimeoutFn(() => {
      restartTimer = null;
      if (!state.stopping) launch();
    }, delayMs);
    if (restartTimer?.unref) restartTimer.unref();
  }

  function launch() {
    // 'error' and 'exit' can both fire for one launch (and for a failed spawn
    // only 'error' does), so collapse them into a single termination.
    let settled = false;
    const settle = (code, signal) => {
      if (settled) return;
      settled = true;
      handleTermination(code, signal);
    };

    let child;
    try {
      child = spawnFn(binary, buildTunnelArgs(), {
        env: buildTunnelEnv({ token }),
        stdio: ['ignore', 'inherit', 'inherit'],
        detached: false,
      });
    } catch (err) {
      log('error', 'cloudflared failed to spawn', { error: err.message, binary });
      settle(null, null);
      return;
    }

    state.child = child;
    state.pid = child.pid ?? null;
    state.startedAt = now();

    child.on('error', (err) => {
      // ENOENT lands here when the binary is missing from the image.
      log('error', 'cloudflared process error', { error: err.message, binary });
      settle(null, null);
    });
    child.on('exit', (code, signal) => settle(code, signal));

    log('info', 'cloudflared tunnel started', {
      pid: state.pid,
      localPort,
      // A token-run tunnel takes its routing from the Cloudflare dashboard, so
      // this is the value the public hostname's service has to point at.
      ingress: `http://localhost:${localPort}`,
    });
    events.emit('cloudflared:started', { pid: state.pid, localPort });
  }

  launch();

  return {
    status() {
      return {
        running: !!state.child,
        pid: state.pid,
        localPort,
        ingress: `http://localhost:${localPort}`,
        restarts: state.restarts,
        restartPending: !!restartTimer,
        exhausted: state.exhausted,
        lastExit: state.lastExit,
      };
    },

    async stop({ graceMs = STOP_GRACE_MS } = {}) {
      state.stopping = true;
      if (restartTimer) {
        clearTimeoutFn(restartTimer);
        restartTimer = null;
      }
      const child = state.child;
      if (!child) return;

      const exited = new Promise((resolve) => child.once('exit', resolve));
      child.kill('SIGTERM');

      let graceTimer = null;
      const grace = new Promise((resolve) => {
        graceTimer = setTimeoutFn(resolve, graceMs);
        if (graceTimer?.unref) graceTimer.unref();
      });
      await Promise.race([exited, grace]);
      if (graceTimer) clearTimeoutFn(graceTimer);

      // cloudflared can sit draining connections past the grace window, and
      // the server's own shutdown watchdog is not far behind.
      if (state.child) child.kill('SIGKILL');
    },
  };
}
