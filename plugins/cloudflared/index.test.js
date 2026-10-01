/**
 * Tests for the cloudflared plugin's register() wiring -- the gating contract:
 * no token means the server starts normally with no tunnel; a token means the
 * tunnel starts against the port the server actually bound.
 */

import { describe, test, expect, beforeEach, afterEach } from '@jest/globals';
import { EventEmitter } from 'node:events';
import { register } from './index.js';

const TOKEN = 'eyJhIjoiZmFrZSIsInQiOiJmYWtlIn0=';

// A fake cloudflared child: never really spawns, stays "alive" until killed.
class FakeChild extends EventEmitter {
  constructor() {
    super();
    this.pid = 4242;
    this.signals = [];
  }

  kill(signal) {
    this.signals.push(signal);
    // Resolve the launcher's stop() promise promptly.
    queueMicrotask(() => this.emit('exit', 0, signal));
    return true;
  }
}

function makeApp() {
  const routes = new Map();
  return {
    routes,
    get(path, handler) { routes.set(path, handler); },
    call(path) {
      const handler = routes.get(path);
      if (!handler) throw new Error(`no route ${path}`);
      let body;
      const res = { json: (payload) => { body = payload; return res; } };
      handler({}, res);
      return body;
    },
  };
}

function makeCtx(settings = {}) {
  const events = new EventEmitter();
  events.emitAsync = async (name, payload) => {
    await Promise.all(events.listeners(name).map((fn) => fn(payload)));
  };
  const logs = [];
  const spawned = [];
  return {
    events,
    log: (level, msg, meta) => logs.push({ level, msg, meta }),
    plugin: { name: 'cloudflared', settings },
    logs,
    spawned,
    // Test seam honoured by index.js.
    __spawnFn: (binary, args, options) => {
      const child = new FakeChild();
      spawned.push({ binary, args, options, child });
      return child;
    },
  };
}

describe('cloudflared register() gating', () => {
  let realToken;

  beforeEach(() => {
    // register() reads the token from process.env; isolate the test from the
    // real environment both ways.
    realToken = process.env.TUNNEL_TOKEN;
    delete process.env.TUNNEL_TOKEN;
    delete process.env.CLOUDFLARED_TOKEN;
  });

  afterEach(() => {
    if (realToken === undefined) delete process.env.TUNNEL_TOKEN;
    else process.env.TUNNEL_TOKEN = realToken;
  });

  test('with no token: registers status, reports disabled, spawns nothing', async () => {
    const app = makeApp();
    const ctx = makeCtx();

    await register(app, ctx);
    // server:started must not spawn a tunnel when disabled.
    ctx.events.emit('server:started', { port: 9377 });

    const status = app.call('/cloudflared/status');
    expect(status.enabled).toBe(false);
    expect(status.running).toBe(false);
    expect(status.reason).toMatch(/TUNNEL_TOKEN/);
    expect(ctx.spawned).toHaveLength(0);
    // A missing token is a normal boot, not an error.
    expect(ctx.logs.some((l) => l.level === 'error')).toBe(false);
  });

  test('with a token: status flips to running against the bound port', async () => {
    process.env.TUNNEL_TOKEN = TOKEN;
    const app = makeApp();
    const ctx = makeCtx();

    await register(app, ctx);

    const before = app.call('/cloudflared/status');
    expect(before.enabled).toBe(true);
    expect(before.running).toBe(false);
    expect(before.reason).toMatch(/binding/);

    ctx.events.emit('server:started', { port: 12345 });

    const after = app.call('/cloudflared/status');
    expect(after.enabled).toBe(true);
    expect(after.running).toBe(true);
    expect(after.localPort).toBe(12345);
    expect(after.ingress).toBe('http://localhost:12345');
    expect(ctx.spawned).toHaveLength(1);
    expect(ctx.spawned[0].args).toEqual(['tunnel', '--no-autoupdate', 'run']);

    await ctx.events.emitAsync('server:shutdown', { signal: 'SIGTERM' });
    expect(ctx.spawned[0].child.signals).toContain('SIGTERM');
  });

  test('never exposes the token through the status endpoint or logs', async () => {
    process.env.TUNNEL_TOKEN = TOKEN;
    const app = makeApp();
    const ctx = makeCtx();

    await register(app, ctx);
    ctx.events.emit('server:started', { port: 9377 });
    const status = app.call('/cloudflared/status');

    expect(JSON.stringify(status)).not.toContain(TOKEN);
    expect(JSON.stringify(ctx.logs)).not.toContain(TOKEN);
    // argv is world-readable; the token must ride in the env instead.
    expect(JSON.stringify(ctx.spawned[0].args)).not.toContain(TOKEN);
    expect(ctx.spawned[0].options.env.TUNNEL_TOKEN).toBe(TOKEN);

    await ctx.events.emitAsync('server:shutdown', { signal: 'SIGTERM' });
  });
});
