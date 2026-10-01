/**
 * Tests for the local proxy relay (lib/proxy-relay.js).
 *
 * The relay fronts an upstream proxy for the browser: the browser only ever
 * speaks plain HTTP to a loopback listener, and the relay dials the real
 * upstream using its own protocol. These tests stand up fake upstream proxies
 * (HTTP CONNECT with auth, SOCKS5 with auth, and a TLS-wrapped HTTP proxy) and
 * drive the relay as the browser would.
 */

import { describe, test, expect, afterEach } from '@jest/globals';
import net from 'net';
import tls from 'tls';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { execFileSync } from 'child_process';
import { createProxyRelay, parseUpstreamServer } from '../../lib/proxy-relay.js';

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      resolve(address.port);
    });
  });
}

/** An origin server that echoes whatever it receives, prefixed with "echo:". */
function startEchoOrigin() {
  const server = net.createServer((socket) => {
    socket.on('data', (chunk) => socket.write(Buffer.concat([Buffer.from('echo:'), chunk])));
    socket.on('error', () => {});
  });
  return { server, port: null };
}

/** Read from a socket until `delim`, leaving any surplus buffered via unshift(). */
function readUntil(socket, delim) {
  const needle = Buffer.from(delim, 'latin1');
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      const idx = buf.indexOf(needle);
      if (idx === -1) return;
      cleanup();
      const rest = buf.subarray(idx + needle.length);
      if (rest.length) socket.unshift(rest);
      resolve(buf.subarray(0, idx + needle.length));
    };
    const onError = (err) => { cleanup(); reject(err); };
    const onClose = () => { cleanup(); reject(new Error('socket closed before delimiter')); };
    function cleanup() {
      socket.off('data', onData);
      socket.off('error', onError);
      socket.off('close', onClose);
    }
    socket.on('data', onData);
    socket.on('error', onError);
    socket.on('close', onClose);
  });
}

function readBytes(socket, n) {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length < n) return;
      cleanup();
      const rest = buf.subarray(n);
      if (rest.length) socket.unshift(rest);
      resolve(buf.subarray(0, n));
    };
    const onError = (err) => { cleanup(); reject(err); };
    const onClose = () => { cleanup(); reject(new Error('socket closed early')); };
    function cleanup() {
      socket.off('data', onData);
      socket.off('error', onError);
      socket.off('close', onClose);
    }
    socket.on('data', onData);
    socket.on('error', onError);
    socket.on('close', onClose);
  });
}

function basic(username, password) {
  return `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;
}

/**
 * A minimal HTTP CONNECT proxy. Records the Proxy-Authorization header it saw.
 */
function startHttpConnectProxy({ requireAuth = null } = {}) {
  const state = { authHeaders: [], connects: [] };
  const handler = (socket) => {
    let buf = Buffer.alloc(0);
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      const idx = buf.indexOf('\r\n\r\n');
      if (idx === -1) return;
      socket.off('data', onData);
      const head = buf.subarray(0, idx).toString('latin1');
      const rest = buf.subarray(idx + 4);
      const [requestLine, ...headerLines] = head.split('\r\n');
      const match = /^CONNECT\s+(\S+)\s+HTTP\/\d\.\d$/i.exec(requestLine);
      if (!match) {
        socket.end('HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n');
        return;
      }
      const authLine = headerLines.find((l) => /^proxy-authorization:/i.test(l));
      state.authHeaders.push(authLine ? authLine.slice(authLine.indexOf(':') + 1).trim() : null);
      if (requireAuth) {
        if (!authLine || authLine.slice(authLine.indexOf(':') + 1).trim() !== basic(requireAuth.username, requireAuth.password)) {
          socket.end('HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n');
          return;
        }
      }
      const [host, port] = match[1].split(':');
      state.connects.push({ host, port: parseInt(port, 10) });
      const upstream = net.connect(parseInt(port, 10), host, () => {
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (rest.length) upstream.write(rest);
        socket.pipe(upstream);
        upstream.pipe(socket);
      });
      upstream.on('error', () => socket.destroy());
    };
    socket.on('data', onData);
    socket.on('error', () => {});
  };
  const server = net.createServer(handler);
  return { server, handler, state };
}

/** A minimal SOCKS5 proxy with optional RFC1929 username/password auth. */
function startSocks5Proxy({ username, password } = {}) {
  const state = { authAttempts: [], connects: [] };
  const handler = (socket) => {
    let buf = Buffer.alloc(0);
    let phase = 'greeting';
    let target = null;

    const pump = () => {
      if (phase === 'greeting') {
        if (buf.length < 2) return;
        const nMethods = buf[1];
        if (buf.length < 2 + nMethods) return;
        const methods = [...buf.subarray(2, 2 + nMethods)];
        buf = buf.subarray(2 + nMethods);
        if (username) {
          if (!methods.includes(0x02)) { socket.end(Buffer.from([0x05, 0xFF])); return; }
          socket.write(Buffer.from([0x05, 0x02]));
          phase = 'auth';
        } else {
          socket.write(Buffer.from([0x05, 0x00]));
          phase = 'request';
        }
      }
      if (phase === 'auth') {
        if (buf.length < 2) return;
        const ulen = buf[1];
        if (buf.length < 2 + ulen + 1) return;
        const plen = buf[2 + ulen];
        if (buf.length < 2 + ulen + 1 + plen) return;
        const user = buf.subarray(2, 2 + ulen).toString('utf8');
        const pass = buf.subarray(2 + ulen + 1, 2 + ulen + 1 + plen).toString('utf8');
        buf = buf.subarray(2 + ulen + 1 + plen);
        state.authAttempts.push({ user, pass });
        if (user !== username || pass !== password) { socket.end(Buffer.from([0x01, 0x01])); return; }
        socket.write(Buffer.from([0x01, 0x00]));
        phase = 'request';
      }
      if (phase === 'request') {
        if (buf.length < 4) return;
        const atyp = buf[3];
        let addrLen;
        if (atyp === 0x01) addrLen = 4;
        else if (atyp === 0x04) addrLen = 16;
        else if (atyp === 0x03) {
          if (buf.length < 5) return;
          addrLen = buf[4];
        } else { socket.end(); return; }
        const addrStart = atyp === 0x03 ? 5 : 4;
        if (buf.length < addrStart + addrLen + 2) return;
        const host = atyp === 0x03
          ? buf.subarray(addrStart, addrStart + addrLen).toString('utf8')
          : buf.subarray(addrStart, addrStart + addrLen).join('.');
        const port = buf.readUInt16BE(addrStart + addrLen);
        const rest = buf.subarray(addrStart + addrLen + 2);
        buf = Buffer.alloc(0);
        phase = 'tunnel';
        target = { host, port };
        state.connects.push(target);
        const upstream = net.connect(port, host, () => {
          socket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
          if (rest.length) upstream.write(rest);
          socket.pipe(upstream);
          upstream.pipe(socket);
        });
        upstream.on('error', () => socket.destroy());
        return;
      }
    };

    socket.on('data', (chunk) => {
      if (phase === 'tunnel') return;
      buf = Buffer.concat([buf, chunk]);
      pump();
    });
    socket.on('error', () => {});
  };
  const server = net.createServer(handler);
  return { server, handler, state };
}

// A throwaway self-signed cert for the TLS-upstream test. Generated at runtime
// with openssl so no key material lives in the repo; the TLS test is skipped if
// openssl is unavailable.
function makeSelfSignedCert() {
  let dir;
  try {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-cert-'));
    const keyPath = path.join(dir, 'key.pem');
    const certPath = path.join(dir, 'cert.pem');
    execFileSync('openssl', [
      'req', '-x509', '-newkey', 'rsa:2048',
      '-keyout', keyPath, '-out', certPath,
      '-days', '2', '-nodes',
      '-subj', '/CN=127.0.0.1',
      '-addext', 'subjectAltName=IP:127.0.0.1',
    ], { stdio: 'ignore' });
    return { key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) };
  } catch {
    return null;
  } finally {
    if (dir) { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ } }
  }
}

const TEST_TLS_CERT = makeSelfSignedCert();

// ---------------------------------------------------------------------------
// Registers open servers/relays for teardown
// ---------------------------------------------------------------------------

const openServers = [];
const openRelays = [];

function track(server) { openServers.push(server); return server; }
function trackRelay(relay) { openRelays.push(relay); return relay; }

afterEach(async () => {
  for (const relay of openRelays.splice(0)) relay.close();
  await Promise.all(openServers.splice(0).map((server) => new Promise((resolve) => {
    try { server.close(() => resolve()); } catch { resolve(); }
  })));
});

async function connectThroughRelay(relayPort, targetHost, targetPort, { auth } = {}) {
  const socket = net.connect(relayPort, '127.0.0.1');
  await new Promise((resolve, reject) => { socket.once('connect', resolve); socket.once('error', reject); });
  let head = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n`;
  if (auth) head += `Proxy-Authorization: ${auth}\r\n`;
  head += '\r\n';
  socket.write(head);
  const response = (await readUntil(socket, '\r\n\r\n')).toString('latin1');
  return { socket, response };
}

// ---------------------------------------------------------------------------
// parseUpstreamServer
// ---------------------------------------------------------------------------

describe('parseUpstreamServer', () => {
  test('parses each supported scheme', () => {
    expect(parseUpstreamServer('http://proxy.example.com:8080'))
      .toEqual({ protocol: 'http', host: 'proxy.example.com', port: 8080 });
    expect(parseUpstreamServer('https://proxy.example.com:8443'))
      .toEqual({ protocol: 'https', host: 'proxy.example.com', port: 8443 });
    expect(parseUpstreamServer('socks5://proxy.example.com:1080'))
      .toEqual({ protocol: 'socks5', host: 'proxy.example.com', port: 1080 });
    expect(parseUpstreamServer('socks4://proxy.example.com:1080'))
      .toEqual({ protocol: 'socks4', host: 'proxy.example.com', port: 1080 });
  });

  test('defaults the port by scheme when omitted', () => {
    expect(parseUpstreamServer('http://proxy.example.com').port).toBe(80);
    expect(parseUpstreamServer('https://proxy.example.com').port).toBe(443);
  });

  test('assumes http when no scheme is present', () => {
    expect(parseUpstreamServer('proxy.example.com:3128'))
      .toEqual({ protocol: 'http', host: 'proxy.example.com', port: 3128 });
  });

  test('rejects unsupported or malformed servers', () => {
    expect(parseUpstreamServer('ftp://proxy.example.com:21')).toBeNull();
    expect(parseUpstreamServer('')).toBeNull();
    expect(parseUpstreamServer(null)).toBeNull();
    expect(parseUpstreamServer('http://')).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// mapProxy
// ---------------------------------------------------------------------------

describe('createProxyRelay.mapProxy', () => {
  test('rewrites the server to loopback and drops credentials', async () => {
    const relay = trackRelay(createProxyRelay());
    const mapped = await relay.mapProxy({
      server: 'http://upstream.example.com:8080',
      username: 'user',
      password: 'pass',
      sessionId: 'sess-1',
    });
    expect(mapped.server).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
    expect(mapped.username).toBeUndefined();
    expect(mapped.password).toBeUndefined();
    expect(mapped.sessionId).toBe('sess-1');
  });

  test('reuses one listener for identical upstream specs', async () => {
    const relay = trackRelay(createProxyRelay());
    const first = await relay.mapProxy({ server: 'socks5://upstream.example.com:1080', username: 'u', password: 'p' });
    const second = await relay.mapProxy({ server: 'socks5://upstream.example.com:1080', username: 'u', password: 'p' });
    expect(second.server).toBe(first.server);
    expect(relay.stats().listeners).toBe(1);
  });

  test('allocates distinct listeners when the session username rotates', async () => {
    const relay = trackRelay(createProxyRelay());
    const a = await relay.mapProxy({ server: 'http://gate.example.com:7000', username: 'user-a', password: 'p' });
    const b = await relay.mapProxy({ server: 'http://gate.example.com:7000', username: 'user-b', password: 'p' });
    expect(a.server).not.toBe(b.server);
    expect(relay.stats().listeners).toBe(2);
  });

  test('passes the proxy through untouched when disabled', async () => {
    const relay = trackRelay(createProxyRelay({ enabled: false }));
    const proxy = { server: 'http://upstream.example.com:8080', username: 'u', password: 'p' };
    expect(await relay.mapProxy(proxy)).toBe(proxy);
    expect(relay.stats().listeners).toBe(0);
  });

  test('passes null and unusable proxies through', async () => {
    const relay = trackRelay(createProxyRelay());
    expect(await relay.mapProxy(null)).toBeNull();
    const weird = { server: 'not a url' };
    expect(await relay.mapProxy(weird)).toBe(weird);
  });
});

// ---------------------------------------------------------------------------
// End-to-end tunneling
// ---------------------------------------------------------------------------

describe('relay tunneling through an HTTP upstream', () => {
  test('opens a CONNECT tunnel to the origin', async () => {
    const origin = startEchoOrigin();
    const originPort = await listen(track(origin.server));
    const proxy = startHttpConnectProxy();
    const proxyPort = await listen(track(proxy.server));

    const relay = trackRelay(createProxyRelay());
    const mapped = await relay.mapProxy({ server: `http://127.0.0.1:${proxyPort}` });
    const relayPort = parseInt(new URL(mapped.server).port, 10);

    const { socket, response } = await connectThroughRelay(relayPort, '127.0.0.1', originPort);
    expect(response).toMatch(/^HTTP\/1\.1 200/);
    socket.write('hello');
    expect((await readBytes(socket, 'echo:hello'.length)).toString('utf8')).toBe('echo:hello');
    socket.destroy();

    expect(proxy.state.connects).toEqual([{ host: '127.0.0.1', port: originPort }]);
  });

  test('forwards the upstream credentials configured for the route', async () => {
    const origin = startEchoOrigin();
    const originPort = await listen(track(origin.server));
    const proxy = startHttpConnectProxy({ requireAuth: { username: 'alice', password: 's3cret' } });
    const proxyPort = await listen(track(proxy.server));

    const relay = trackRelay(createProxyRelay());
    const mapped = await relay.mapProxy({
      server: `http://127.0.0.1:${proxyPort}`,
      username: 'alice',
      password: 's3cret',
    });
    const relayPort = parseInt(new URL(mapped.server).port, 10);

    const { socket, response } = await connectThroughRelay(relayPort, '127.0.0.1', originPort);
    expect(response).toMatch(/^HTTP\/1\.1 200/);
    socket.write('ping');
    expect((await readBytes(socket, 'echo:ping'.length)).toString('utf8')).toBe('echo:ping');
    socket.destroy();

    expect(proxy.state.authHeaders).toEqual([basic('alice', 's3cret')]);
  });

  test('reports a gateway error when the upstream rejects the tunnel', async () => {
    const origin = startEchoOrigin();
    const originPort = await listen(track(origin.server));
    const proxy = startHttpConnectProxy({ requireAuth: { username: 'alice', password: 'right' } });
    const proxyPort = await listen(track(proxy.server));

    const relay = trackRelay(createProxyRelay());
    const mapped = await relay.mapProxy({
      server: `http://127.0.0.1:${proxyPort}`,
      username: 'alice',
      password: 'wrong',
    });
    const relayPort = parseInt(new URL(mapped.server).port, 10);

    const { socket, response } = await connectThroughRelay(relayPort, '127.0.0.1', originPort);
    expect(response).toMatch(/^HTTP\/1\.1 502/);
    socket.destroy();
  });
});

describe('relay tunneling through a SOCKS5 upstream with auth', () => {
  test('performs RFC1929 auth and tunnels the origin traffic', async () => {
    const origin = startEchoOrigin();
    const originPort = await listen(track(origin.server));
    const socks = startSocks5Proxy({ username: 'socksuser', password: 'sockspass' });
    const socksPort = await listen(track(socks.server));

    const relay = trackRelay(createProxyRelay());
    const mapped = await relay.mapProxy({
      server: `socks5://127.0.0.1:${socksPort}`,
      username: 'socksuser',
      password: 'sockspass',
    });
    const relayPort = parseInt(new URL(mapped.server).port, 10);

    const { socket, response } = await connectThroughRelay(relayPort, '127.0.0.1', originPort);
    expect(response).toMatch(/^HTTP\/1\.1 200/);
    socket.write('data');
    expect((await readBytes(socket, 'echo:data'.length)).toString('utf8')).toBe('echo:data');
    socket.destroy();

    expect(socks.state.authAttempts).toEqual([{ user: 'socksuser', pass: 'sockspass' }]);
    expect(socks.state.connects).toEqual([{ host: '127.0.0.1', port: originPort }]);
  });

  test('fails the tunnel when upstream credentials are wrong', async () => {
    const origin = startEchoOrigin();
    const originPort = await listen(track(origin.server));
    const socks = startSocks5Proxy({ username: 'socksuser', password: 'right' });
    const socksPort = await listen(track(socks.server));

    const relay = trackRelay(createProxyRelay());
    const mapped = await relay.mapProxy({
      server: `socks5://127.0.0.1:${socksPort}`,
      username: 'socksuser',
      password: 'wrong',
    });
    const relayPort = parseInt(new URL(mapped.server).port, 10);

    const { socket, response } = await connectThroughRelay(relayPort, '127.0.0.1', originPort);
    expect(response).toMatch(/^HTTP\/1\.1 502/);
    socket.destroy();
  });

  test('rewrites absolute-form HTTP to origin-form and strips proxy auth', async () => {
    let receivedRequest = null;
    const originServer = net.createServer((socket) => {
      const chunks = [];
      socket.on('data', (chunk) => {
        chunks.push(chunk);
        const text = Buffer.concat(chunks).toString('latin1');
        if (!text.includes('\r\n\r\n')) return;
        receivedRequest = text;
        socket.end('HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok');
      });
      socket.on('error', () => {});
    });
    const originPort = await listen(track(originServer));

    const socks = startSocks5Proxy({ username: 'u', password: 'p' });
    const socksPort = await listen(track(socks.server));
    const relay = trackRelay(createProxyRelay());
    const mapped = await relay.mapProxy({ server: `socks5://127.0.0.1:${socksPort}`, username: 'u', password: 'p' });
    const relayPort = parseInt(new URL(mapped.server).port, 10);

    const socket = net.connect(relayPort, '127.0.0.1');
    await new Promise((resolve, reject) => { socket.once('connect', resolve); socket.once('error', reject); });
    socket.write(
      `GET http://127.0.0.1:${originPort}/some/path?q=1 HTTP/1.1\r\n` +
      `Host: 127.0.0.1:${originPort}\r\n` +
      `Proxy-Authorization: ${basic('u', 'p')}\r\n` +
      `Proxy-Connection: keep-alive\r\n\r\n`
    );
    const responseText = (await readUntil(socket, '\r\n\r\n')).toString('latin1');
    expect(responseText).toMatch(/^HTTP\/1\.1 200/);
    socket.destroy();

    // The origin only answers after it has seen the full request line + headers,
    // so by the time the head came back this is populated.
    expect(receivedRequest).not.toBeNull();
    expect(receivedRequest.startsWith('GET /some/path?q=1 HTTP/1.1')).toBe(true);
    expect(receivedRequest).not.toMatch(/proxy-authorization/i);
    expect(receivedRequest).not.toMatch(/proxy-connection/i);
    expect(receivedRequest).toMatch(/Host: 127\.0\.0\.1/);
  });
});

describe('relay tunneling through an HTTPS (TLS) upstream', () => {
  const maybe = TEST_TLS_CERT ? test : test.skip;

  maybe('completes a full TLS handshake to the upstream proxy', async () => {
    const origin = startEchoOrigin();
    const originPort = await listen(track(origin.server));

    const proxy = startHttpConnectProxy({ requireAuth: { username: 'tlsuser', password: 'tlspass' } });
    const tlsServer = tls.createServer(
      { key: TEST_TLS_CERT.key, cert: TEST_TLS_CERT.cert },
      proxy.handler
    );
    const tlsPort = await listen(track(tlsServer));

    const relay = trackRelay(createProxyRelay({ tlsRejectUnauthorized: false }));
    const mapped = await relay.mapProxy({
      server: `https://127.0.0.1:${tlsPort}`,
      username: 'tlsuser',
      password: 'tlspass',
    });
    const relayPort = parseInt(new URL(mapped.server).port, 10);

    const { socket, response } = await connectThroughRelay(relayPort, '127.0.0.1', originPort);
    expect(response).toMatch(/^HTTP\/1\.1 200/);
    socket.write('secure');
    expect((await readBytes(socket, 'echo:secure'.length)).toString('utf8')).toBe('echo:secure');
    socket.destroy();

    expect(proxy.state.authHeaders).toEqual([basic('tlsuser', 'tlspass')]);
  });

  maybe('rejects an untrusted upstream certificate by default', async () => {
    const origin = startEchoOrigin();
    const originPort = await listen(track(origin.server));

    const proxy = startHttpConnectProxy();
    const tlsServer = tls.createServer({ key: TEST_TLS_CERT.key, cert: TEST_TLS_CERT.cert }, proxy.handler);
    const tlsPort = await listen(track(tlsServer));

    // Default relay verifies certificates, so the self-signed upstream fails.
    const relay = trackRelay(createProxyRelay());
    const mapped = await relay.mapProxy({ server: `https://127.0.0.1:${tlsPort}` });
    const relayPort = parseInt(new URL(mapped.server).port, 10);

    const { socket, response } = await connectThroughRelay(relayPort, '127.0.0.1', originPort);
    expect(response).toMatch(/^HTTP\/1\.1 502/);
    socket.destroy();
  });
});

describe('relay error handling', () => {
  test('reports a gateway error when the upstream is unreachable', async () => {
    // Reserve a port, then close it so nothing is listening there.
    const probe = net.createServer();
    const deadPort = await listen(probe);
    await new Promise((resolve) => probe.close(resolve));

    const relay = trackRelay(createProxyRelay());
    const mapped = await relay.mapProxy({ server: `http://127.0.0.1:${deadPort}` });
    const relayPort = parseInt(new URL(mapped.server).port, 10);

    const { socket, response } = await connectThroughRelay(relayPort, '127.0.0.1', 80);
    expect(response).toMatch(/^HTTP\/1\.1 502/);
    socket.destroy();
  });

  test('rejects a malformed client request', async () => {
    const proxy = startHttpConnectProxy();
    const proxyPort = await listen(track(proxy.server));
    const relay = trackRelay(createProxyRelay());
    const mapped = await relay.mapProxy({ server: `http://127.0.0.1:${proxyPort}` });
    const relayPort = parseInt(new URL(mapped.server).port, 10);

    const socket = net.connect(relayPort, '127.0.0.1');
    await new Promise((resolve, reject) => { socket.once('connect', resolve); socket.once('error', reject); });
    socket.write('NOT-A-REQUEST\r\n\r\n');
    const response = (await readUntil(socket, '\r\n\r\n')).toString('latin1');
    expect(response).toMatch(/^HTTP\/1\.1 400/);
    socket.destroy();
  });
});
