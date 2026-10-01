/**
 * Tests for the cloudflared launcher.
 *
 * The supervisor is driven with an injected spawn + timer so restart behaviour
 * is deterministic and no real cloudflared process is ever started.
 */

import { describe, test, expect, beforeEach } from '@jest/globals';
import { EventEmitter } from 'node:events';
import {
  resolveCloudflaredConfig,
  buildTunnelArgs,
  buildTunnelEnv,
  restartDelayMs,
  startTunnel,
} from './cloudflared-launcher.js';

const TOKEN = 'eyJhIjoiZmFrZSIsInQiOiJmYWtlIiwicyI6ImZha2UifQ==';

// ---------------------------------------------------------------------------
// Config resolution
// ---------------------------------------------------------------------------

describe('resolveCloudflaredConfig', () => {
  test('stays disabled when no token is present', () => {
    const config = resolveCloudflaredConfig({}, {});
    expect(config.enabled).toBe(false);
    expect(config.token).toBe('');
    expect(config.tokenSource).toBeNull();
  });

  test('enables on TUNNEL_TOKEN', () => {
    const config = resolveCloudflaredConfig({}, { TUNNEL_TOKEN: TOKEN });
    expect(config.enabled).toBe(true);
    expect(config.token).toBe(TOKEN);
    expect(config.tokenSource).toBe('TUNNEL_TOKEN');
  });

  test('accepts CLOUDFLARED_TOKEN as an alias', () => {
    const config = resolveCloudflaredConfig({}, { CLOUDFLARED_TOKEN: TOKEN });
    expect(config.enabled).toBe(true);
    expect(config.token).toBe(TOKEN);
    expect(config.tokenSource).toBe('CLOUDFLARED_TOKEN');
  });

  test('prefers TUNNEL_TOKEN over the alias', () => {
    const config = resolveCloudflaredConfig({}, { TUNNEL_TOKEN: 'primary', CLOUDFLARED_TOKEN: 'alias' });
    expect(config.token).toBe('primary');
    expect(config.tokenSource).toBe('TUNNEL_TOKEN');
  });

  test('treats a whitespace-only token as absent', () => {
    const config = resolveCloudflaredConfig({}, { TUNNEL_TOKEN: '   \n' });
    expect(config.enabled).toBe(false);
  });

  test('trims surrounding whitespace from the token', () => {
    // Tokens pasted into a compose file or a .env often carry a trailing newline.
    const config = resolveCloudflaredConfig({}, { TUNNEL_TOKEN: `  ${TOKEN}\n` });
    expect(config.token).toBe(TOKEN);
  });

  test('ignores a token in plugin settings', () => {
    // camofox.config.json is committed; a credential must not be read from it.
    const config = resolveCloudflaredConfig({ token: TOKEN }, {});
    expect(config.enabled).toBe(false);
    expect(config.token).toBe('');
  });

  test('defaults the binary to cloudflared on PATH', () => {
    expect(resolveCloudflaredConfig({}, {}).binary).toBe('cloudflared');
  });

  test('takes the binary from env over plugin settings', () => {
    const config = resolveCloudflaredConfig(
      { binary: '/from/settings' },
      { CLOUDFLARED_BIN: '/from/env' }
    );
    expect(config.binary).toBe('/from/env');
  });

  test('falls back to the plugin-settings binary', () => {
    expect(resolveCloudflaredConfig({ binary: '/opt/cloudflared' }, {}).binary).toBe('/opt/cloudflared');
  });

  test('treats an unset or unparsable restart budget as unlimited', () => {
    expect(resolveCloudflaredConfig({}, {}).maxRestarts).toBe(0);
    expect(resolveCloudflaredConfig({}, { CLOUDFLARED_MAX_RESTARTS: 'lots' }).maxRestarts).toBe(0);
    expect(resolveCloudflaredConfig({}, { CLOUDFLARED_MAX_RESTARTS: '-3' }).maxRestarts).toBe(0);
  });

  test('reads a numeric restart budget', () => {
    expect(resolveCloudflaredConfig({}, { CLOUDFLARED_MAX_RESTARTS: '5' }).maxRestarts).toBe(5);
  });
});

// ---------------------------------------------------------------------------
// Process invocation
// ---------------------------------------------------------------------------

describe('buildTunnelArgs', () => {
  test('uses the canonical token-run invocation with autoupdate off', () => {
    expect(buildTunnelArgs()).toEqual(['tunnel', '--no-autoupdate', 'run']);
  });

  test('never carries the token in argv', () => {
    // argv is world-readable via ps; the token rides in the environment instead.
    expect(buildTunnelArgs().join(' ')).not.toContain(TOKEN);
    expect(buildTunnelArgs()).not.toContain('--token');
  });
});

describe('buildTunnelEnv', () => {
  test('passes the token as TUNNEL_TOKEN', () => {
    expect(buildTunnelEnv({ token: TOKEN }, {}).TUNNEL_TOKEN).toBe(TOKEN);
  });

  test('forwards PATH and HOME', () => {
    const env = buildTunnelEnv({ token: TOKEN }, { PATH: '/usr/bin', HOME: '/root' });
    expect(env.PATH).toBe('/usr/bin');
    expect(env.HOME).toBe('/root');
  });

  test("forwards cloudflared's own TUNNEL_* knobs", () => {
    const env = buildTunnelEnv({ token: TOKEN }, {
      TUNNEL_REGION: 'us',
      TUNNEL_TRANSPORT_PROTOCOL: 'http2',
      TUNNEL_METRICS: '127.0.0.1:20241',
      TUNNEL_EDGE_IP_VERSION: '4',
    });
    expect(env.TUNNEL_REGION).toBe('us');
    expect(env.TUNNEL_TRANSPORT_PROTOCOL).toBe('http2');
    expect(env.TUNNEL_METRICS).toBe('127.0.0.1:20241');
    expect(env.TUNNEL_EDGE_IP_VERSION).toBe('4');
  });

  test('lets the resolved token win over a stale TUNNEL_TOKEN in the parent env', () => {
    const env = buildTunnelEnv({ token: 'resolved' }, { TUNNEL_TOKEN: 'stale' });
    expect(env.TUNNEL_TOKEN).toBe('resolved');
  });

  test('withholds unrelated secrets from the tunnel process', () => {
    // cloudflared is the one process here that talks to the public internet.
    const env = buildTunnelEnv({ token: TOKEN }, {
      PROXY_PASSWORD: 'proxy-secret',
      PROXY_USERNAME: 'proxy-user',
      CAMOFOX_API_KEY: 'api-secret',
      CAMOFOX_ADMIN_KEY: 'admin-secret',
      VNC_PASSWORD: 'vnc-secret',
      CLOUDFLARED_TOKEN: 'alias-token',
    });
    expect(env).not.toHaveProperty('PROXY_PASSWORD');
    expect(env).not.toHaveProperty('PROXY_USERNAME');
    expect(env).not.toHaveProperty('CAMOFOX_API_KEY');
    expect(env).not.toHaveProperty('CAMOFOX_ADMIN_KEY');
    expect(env).not.toHaveProperty('VNC_PASSWORD');
    expect(env).not.toHaveProperty('CLOUDFLARED_TOKEN');
    expect(Object.values(env)).not.toContain('proxy-secret');
  });

  test('drops undefined values rather than stringifying them', () => {
    const env = buildTunnelEnv({ token: TOKEN }, { PATH: undefined, HOME: null });
    expect(env).not.toHaveProperty('PATH');
    expect(env).not.toHaveProperty('HOME');
  });
});

// ---------------------------------------------------------------------------
// Backoff
// ---------------------------------------------------------------------------

describe('restartDelayMs', () => {
  test('doubles per consecutive failure', () => {
    expect(restartDelayMs(1)).toBe(1000);
    expect(restartDelayMs(2)).toBe(2000);
    expect(restartDelayMs(3)).toBe(4000);
    expect(restartDelayMs(4)).toBe(8000);
  });

  test('caps the delay', () => {
    expect(restartDelayMs(50)).toBe(60000);
  });

  test('clamps a zero or negative attempt to the base delay', () => {
    expect(restartDelayMs(0)).toBe(1000);
    expect(restartDelayMs(-1)).toBe(1000);
  });
});

// ---------------------------------------------------------------------------
// Supervisor
// ---------------------------------------------------------------------------

class FakeChild extends EventEmitter {
  constructor(pid) {
    super();
    this.pid = pid;
    this.signals = [];
  }

  kill(signal) {
    this.signals.push(signal);
    return true;
  }
}

function makeHarness({ maxRestarts = 0, spawnImpl } = {}) {
  const spawned = [];
  const logs = [];
  const emitted = [];
  const timers = [];
  let nextPid = 1000;
  let clock = 0;

  const events = { emit: (name, payload) => emitted.push({ name, payload }) };

  const defaultSpawn = () => {
    const child = new FakeChild(nextPid++);
    return child;
  };

  const tunnel = startTunnel({
    binary: '/usr/local/bin/cloudflared',
    token: TOKEN,
    localPort: 9377,
    maxRestarts,
    log: (level, msg, meta) => logs.push({ level, msg, meta }),
    events,
    spawnFn: (binary, args, options) => {
      const child = (spawnImpl || defaultSpawn)(binary, args, options);
      spawned.push({ binary, args, options, child });
      return child;
    },
    setTimeoutFn: (fn, ms) => {
      const timer = { fn, ms, cancelled: false };
      timers.push(timer);
      return timer;
    },
    clearTimeoutFn: (timer) => {
      if (timer) timer.cancelled = true;
    },
    now: () => clock,
  });

  return {
    tunnel,
    spawned,
    logs,
    emitted,
    timers,
    advance(ms) { clock += ms; },
    setClock(ms) { clock = ms; },
    /** Fire the newest pending restart timer. */
    runPendingTimer() {
      const timer = timers.filter((t) => !t.cancelled).pop();
      if (!timer) throw new Error('no pending timer');
      timer.cancelled = true;
      timer.fn();
      return timer;
    },
    lastChild() { return spawned[spawned.length - 1].child; },
  };
}

describe('startTunnel', () => {
  let harness;

  beforeEach(() => {
    harness = makeHarness();
  });

  test('spawns cloudflared with the configured binary and canonical args', () => {
    expect(harness.spawned).toHaveLength(1);
    expect(harness.spawned[0].binary).toBe('/usr/local/bin/cloudflared');
    expect(harness.spawned[0].args).toEqual(['tunnel', '--no-autoupdate', 'run']);
  });

  test('hands the token to the child through the environment only', () => {
    const { args, options } = harness.spawned[0];
    expect(options.env.TUNNEL_TOKEN).toBe(TOKEN);
    expect(JSON.stringify(args)).not.toContain(TOKEN);
  });

  test('reports running state and the ingress the dashboard must target', () => {
    const status = harness.tunnel.status();
    expect(status.running).toBe(true);
    expect(status.localPort).toBe(9377);
    expect(status.ingress).toBe('http://localhost:9377');
    expect(status.restarts).toBe(0);
    expect(status.lastExit).toBeNull();
  });

  test('never logs the token', () => {
    expect(JSON.stringify(harness.logs)).not.toContain(TOKEN);
  });

  test('emits cloudflared:started with the pid', () => {
    const started = harness.emitted.find((e) => e.name === 'cloudflared:started');
    expect(started.payload.localPort).toBe(9377);
    expect(started.payload.pid).toBe(harness.spawned[0].child.pid);
  });

  test('restarts after the process exits', () => {
    harness.lastChild().emit('exit', 1, null);
    expect(harness.tunnel.status().running).toBe(false);
    expect(harness.tunnel.status().restartPending).toBe(true);

    harness.runPendingTimer();
    expect(harness.spawned).toHaveLength(2);
    expect(harness.tunnel.status().running).toBe(true);
    expect(harness.tunnel.status().restarts).toBe(1);
  });

  test('backs off further on each successive quick crash', () => {
    harness.lastChild().emit('exit', 1, null);
    expect(harness.timers[0].ms).toBe(1000);
    harness.runPendingTimer();

    harness.lastChild().emit('exit', 1, null);
    expect(harness.timers[1].ms).toBe(2000);
    harness.runPendingTimer();

    harness.lastChild().emit('exit', 1, null);
    expect(harness.timers[2].ms).toBe(4000);
  });

  test('resets the backoff after a run that stayed up', () => {
    // A tunnel that survived an hour and then dropped is not a crash loop.
    harness.lastChild().emit('exit', 1, null);
    expect(harness.timers[0].ms).toBe(1000);
    harness.runPendingTimer();

    harness.advance(3_600_000);
    harness.lastChild().emit('exit', 1, null);
    expect(harness.timers[1].ms).toBe(1000);
  });

  test('restarts when the spawn fails outright', () => {
    // ENOENT on a missing binary surfaces as 'error', and 'exit' may never fire.
    harness.lastChild().emit('error', new Error('spawn cloudflared ENOENT'));
    expect(harness.tunnel.status().running).toBe(false);
    harness.runPendingTimer();
    expect(harness.spawned).toHaveLength(2);
  });

  test('counts a single termination when error and exit both fire', () => {
    const child = harness.lastChild();
    child.emit('error', new Error('boom'));
    child.emit('exit', 1, null);
    expect(harness.tunnel.status().restarts).toBe(1);
    expect(harness.timers.filter((t) => !t.cancelled)).toHaveLength(1);
  });

  test('survives a synchronous spawn throw', () => {
    let calls = 0;
    const thrower = makeHarness({
      spawnImpl: () => {
        calls += 1;
        throw new Error('EACCES');
      },
    });
    expect(calls).toBe(1);
    expect(thrower.tunnel.status().running).toBe(false);
    expect(thrower.tunnel.status().restartPending).toBe(true);
  });

  test('stops restarting once the budget is spent', () => {
    const limited = makeHarness({ maxRestarts: 2 });
    limited.lastChild().emit('exit', 1, null);
    limited.runPendingTimer();
    limited.lastChild().emit('exit', 1, null);
    limited.runPendingTimer();
    expect(limited.spawned).toHaveLength(3);
    expect(limited.tunnel.status().restarts).toBe(2);

    limited.lastChild().emit('exit', 1, null);
    expect(limited.tunnel.status().exhausted).toBe(true);
    expect(limited.tunnel.status().restartPending).toBe(false);
    expect(limited.spawned).toHaveLength(3);
  });

  test('records why the process last went away', () => {
    harness.setClock(500);
    harness.lastChild().emit('exit', 137, 'SIGKILL');
    expect(harness.tunnel.status().lastExit).toEqual({ code: 137, signal: 'SIGKILL', ranForMs: 500 });
  });

  test('stop() terminates the child and cancels a pending restart', async () => {
    const child = harness.lastChild();
    const stopped = harness.tunnel.stop();
    expect(child.signals).toContain('SIGTERM');
    child.emit('exit', 0, 'SIGTERM');
    await stopped;

    expect(harness.spawned).toHaveLength(1);
    expect(harness.tunnel.status().running).toBe(false);
    expect(harness.tunnel.status().restartPending).toBe(false);
  });

  test('stop() prevents a queued restart from firing', async () => {
    harness.lastChild().emit('exit', 1, null);
    expect(harness.tunnel.status().restartPending).toBe(true);

    await harness.tunnel.stop();
    expect(harness.timers.every((t) => t.cancelled)).toBe(true);
    expect(harness.spawned).toHaveLength(1);
  });

  test('stop() is a no-op when nothing is running', async () => {
    harness.lastChild().emit('exit', 0, null);
    await expect(harness.tunnel.stop()).resolves.toBeUndefined();
  });

  test('escalates to SIGKILL when the child ignores SIGTERM', async () => {
    const child = harness.lastChild();
    const stopped = harness.tunnel.stop({ graceMs: 10 });
    // Fire the grace timer without the child ever exiting.
    harness.runPendingTimer();
    await stopped;
    expect(child.signals).toEqual(['SIGTERM', 'SIGKILL']);
  });
});
