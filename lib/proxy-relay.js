import net from 'net';
import tls from 'tls';
import { WebSocket, createWebSocketStream } from 'ws';

// ---------------------------------------------------------------------------
// Local proxy relay
// ---------------------------------------------------------------------------
//
// Camoufox (Firefox) can only talk to a plain HTTP proxy it understands. Some
// upstream proxies need a protocol the browser handles poorly or not at all --
// an HTTPS proxy (full TLS to the proxy itself) or a SOCKS5 proxy that requires
// username/password auth.
//
// This module keeps the browser off the real proxy entirely. For every distinct
// upstream endpoint it opens a throwaway listener on 127.0.0.1; the browser is
// pointed at that listener as a plain, unauthenticated HTTP proxy, and the relay
// dials the real upstream using the endpoint's own protocol:
//
//   browser --HTTP--> 127.0.0.1:<port> --(http | https+TLS | socks4 | socks5)--> upstream
//
// Listeners are keyed by the *full* upstream spec (protocol, host, port, and
// credentials), so per-context rotation is preserved without depending on the
// browser forwarding Proxy-Authorization: each rotated session simply gets its
// own local port that already knows which upstream credentials to use.
// ---------------------------------------------------------------------------

const CRLF = '\r\n';
const HEAD_DELIM = Buffer.from('\r\n\r\n', 'latin1');
const MAX_HEAD_BYTES = 64 * 1024;

const DEFAULT_LISTEN_HOST = '127.0.0.1';
const DEFAULT_MAX_LISTENERS = 256;
const DEFAULT_IDLE_TTL_MS = 10 * 60 * 1000;
const DEFAULT_CONNECT_TIMEOUT_MS = 30 * 1000;

const PROXY_SCHEMES = new Set(['http', 'https', 'socks4', 'socks5', 'ws', 'wss']);

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function defaultPortForScheme(scheme) {
  if (scheme === 'https' || scheme === 'wss') return 443;
  if (scheme === 'http' || scheme === 'ws') return 80;
  return 0;
}

/**
 * Parse a Playwright-style proxy `server` string (e.g. "socks5://host:1080")
 * into the pieces the relay needs. Returns null when it cannot be understood.
 */
export function parseUpstreamServer(server) {
  if (!server || typeof server !== 'string') return null;
  let url;
  try {
    url = new URL(server.includes('://') ? server : `http://${server}`);
  } catch {
    return null;
  }
  const protocol = String(url.protocol || '').replace(/:$/, '').toLowerCase();
  if (!PROXY_SCHEMES.has(protocol)) return null;
  const host = url.hostname;
  if (!host) return null;
  const port = url.port ? parseInt(url.port, 10) : defaultPortForScheme(protocol);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) return null;
  return { protocol, host, port };
}

function splitHostPort(value) {
  if (!value) return null;
  const trimmed = String(value).trim();
  // [::1]:8080
  const v6 = /^\[(.+)\]:(\d+)$/.exec(trimmed);
  if (v6) return { host: v6[1], port: parseInt(v6[2], 10) };
  const idx = trimmed.lastIndexOf(':');
  if (idx === -1) return { host: trimmed, port: 0 };
  const host = trimmed.slice(0, idx);
  const port = parseInt(trimmed.slice(idx + 1), 10);
  if (!Number.isInteger(port)) return null;
  return { host, port };
}

function ipv6ToBuffer(ip) {
  const [headPart, tailPart] = ip.split('::');
  const head = headPart ? headPart.split(':').filter(Boolean) : [];
  const tail = tailPart ? tailPart.split(':').filter(Boolean) : [];
  const fill = tailPart !== undefined ? Math.max(0, 8 - head.length - tail.length) : 0;
  const groups = [...head, ...new Array(fill).fill('0'), ...tail];
  const buf = Buffer.alloc(16);
  for (let i = 0; i < 8; i++) buf.writeUInt16BE(parseInt(groups[i] || '0', 16), i * 2);
  return buf;
}

/** Encode a SOCKS5 destination address (ATYP + address) followed by the port. */
function socks5Destination(host, port) {
  const portBuf = Buffer.alloc(2);
  portBuf.writeUInt16BE(port, 0);
  const version = net.isIP(host);
  if (version === 4) {
    const octets = host.split('.').map(n => parseInt(n, 10));
    return Buffer.concat([Buffer.from([0x01, ...octets]), portBuf]);
  }
  if (version === 6) {
    return Buffer.concat([Buffer.from([0x04]), ipv6ToBuffer(host), portBuf]);
  }
  const name = Buffer.from(host, 'utf8');
  if (name.length > 255) throw new Error(`SOCKS5 target hostname too long: ${host}`);
  return Buffer.concat([Buffer.from([0x03, name.length]), name, portBuf]);
}

function parseBasicAuth(headerValue) {
  if (!headerValue) return null;
  const m = /^Basic\s+(.+)$/i.exec(String(headerValue).trim());
  if (!m) return null;
  let decoded;
  try {
    decoded = Buffer.from(m[1], 'base64').toString('utf8');
  } catch {
    return null;
  }
  const sep = decoded.indexOf(':');
  if (sep === -1) return { username: decoded, password: '' };
  return { username: decoded.slice(0, sep), password: decoded.slice(sep + 1) };
}

function toBasicAuth(username, password) {
  return `Basic ${Buffer.from(`${username}:${password}`, 'utf8').toString('base64')}`;
}

// ---------------------------------------------------------------------------
// SocketReader -- pull-shaped reads over a socket that we later hand to pipe()
// ---------------------------------------------------------------------------

class SocketReader {
  constructor(socket) {
    this.socket = socket;
    this.buffer = Buffer.alloc(0);
    this.pending = null;
    this.error = null;
    this.closed = false;
    this._onData = (chunk) => {
      this.buffer = Buffer.concat([this.buffer, chunk]);
      this._settle();
    };
    this._onError = (err) => {
      this.error = err;
      this._settle();
    };
    this._onClose = () => {
      this.closed = true;
      this._settle();
    };
    socket.on('data', this._onData);
    socket.on('error', this._onError);
    socket.on('close', this._onClose);
  }

  _settle() {
    const pending = this.pending;
    if (!pending) return;
    if (pending.type === 'bytes') {
      if (this.buffer.length >= pending.n) {
        this.pending = null;
        const out = Buffer.from(this.buffer.subarray(0, pending.n));
        this.buffer = this.buffer.subarray(pending.n);
        pending.resolve(out);
        return;
      }
    } else if (pending.type === 'until') {
      const idx = this.buffer.indexOf(pending.delim);
      if (idx !== -1) {
        this.pending = null;
        const end = idx + pending.delim.length;
        const out = Buffer.from(this.buffer.subarray(0, end));
        this.buffer = this.buffer.subarray(end);
        pending.resolve(out);
        return;
      }
      if (this.buffer.length > pending.maxBytes) {
        this.pending = null;
        pending.reject(new Error('relay: request header exceeded limit'));
        return;
      }
    }
    if (this.error) {
      this.pending = null;
      pending.reject(this.error);
      return;
    }
    if (this.closed) {
      this.pending = null;
      pending.reject(new Error('relay: connection closed before handshake completed'));
    }
  }

  readBytes(n) {
    return new Promise((resolve, reject) => {
      this.pending = { type: 'bytes', n, resolve, reject };
      this._settle();
    });
  }

  readUntil(delim, maxBytes = MAX_HEAD_BYTES) {
    return new Promise((resolve, reject) => {
      this.pending = { type: 'until', delim, maxBytes, resolve, reject };
      this._settle();
    });
  }

  /**
   * Stop reading and return whatever is still buffered. The caller owns the
   * socket afterwards (it can unshift() the leftovers and pipe()).
   */
  detach() {
    this.socket.off('data', this._onData);
    this.socket.off('error', this._onError);
    this.socket.off('close', this._onClose);
    this.pending = null;
    const leftover = this.buffer;
    this.buffer = Buffer.alloc(0);
    return leftover;
  }
}

// ---------------------------------------------------------------------------
// Upstream dialing
// ---------------------------------------------------------------------------

function openUpstreamSocket(entry) {
  return new Promise((resolve, reject) => {
    const { host, port, protocol, tlsRejectUnauthorized, connectTimeoutMs } = entry;
    let socket;
    let timer;
    const fail = (err) => {
      if (timer) clearTimeout(timer);
      if (socket) socket.destroy();
      reject(err);
    };
    const onReady = () => {
      if (timer) clearTimeout(timer);
      socket.setTimeout(0);
      socket.off('error', fail);
      socket.setNoDelay(true);
      resolve(socket);
    };
    if (protocol === 'https') {
      socket = tls.connect({
        host,
        port,
        servername: net.isIP(host) ? undefined : host,
        rejectUnauthorized: tlsRejectUnauthorized !== false,
      });
      socket.once('secureConnect', onReady);
    } else {
      socket = net.connect({ host, port });
      socket.once('connect', onReady);
    }
    socket.once('error', fail);
    const timeout = Number.isFinite(connectTimeoutMs) ? connectTimeoutMs : DEFAULT_CONNECT_TIMEOUT_MS;
    timer = setTimeout(() => fail(new Error(`relay: upstream ${host}:${port} connect timeout`)), timeout);
    if (timer.unref) timer.unref();
  });
}

/**
 * Establish a tunnel to targetHost:targetPort through the upstream proxy.
 * Returns { socket, leftover } where leftover holds any bytes the upstream
 * already pushed past the handshake response.
 */
async function dialTunnel(entry, targetHost, targetPort, creds) {
  if (targetPort <= 0 || targetPort > 65535) {
    throw new Error(`relay: invalid target port ${targetPort}`);
  }
  switch (entry.protocol) {
    case 'socks5':
      return dialSocks5(entry, targetHost, targetPort, creds);
    case 'socks4':
      return dialSocks4(entry, targetHost, targetPort, creds);
    case 'ws':
    case 'wss':
      return dialWsTunnel(entry, targetHost, targetPort);
    case 'https':
    case 'http':
    default:
      return dialHttpConnect(entry, targetHost, targetPort, creds);
  }
}

/**
 * Tunnel through a remote WebSocket relay (the BookNetwork Worker's /relay).
 * Instead of dialing a proxy locally, we open a wss to the Worker -- the TLS
 * SNI is the Worker's benign hostname, so the GFW never sees the real target
 * SNI. The Worker runs connect() to the residential proxy out of country and
 * CONNECTs to the target there. The browser's raw TCP bytes ride the WS as
 * binary frames; we expose the socket as a Duplex so the rest of the relay
 * (handshake-free pipe) is unchanged.
 *
 * entry.wsUrl    full ws(s):// endpoint (e.g. wss://relay.booknet.work/relay)
 * entry.proxyId  which residential proxy the Worker should use (pool id)
 * entry.accessKey Bearer the Worker validates against a camofox instance key
 */
function dialWsTunnel(entry, targetHost, targetPort) {
  return new Promise((resolve, reject) => {
    let url;
    try {
      url = new URL(entry.wsUrl);
    } catch {
      reject(new Error(`relay: invalid ws relay URL ${entry.wsUrl}`));
      return;
    }
    url.searchParams.set('target', `${targetHost}:${targetPort}`);
    if (entry.proxyId !== undefined && entry.proxyId !== null) {
      url.searchParams.set('proxy', String(entry.proxyId));
    }
    const headers = {};
    if (entry.accessKey) headers.Authorization = `Bearer ${entry.accessKey}`;

    const ws = new WebSocket(url.toString(), {
      headers,
      perMessageDeflate: false,
      handshakeTimeout: entry.connectTimeoutMs || DEFAULT_CONNECT_TIMEOUT_MS,
    });

    let settled = false;
    ws.once('open', () => {
      settled = true;
      const duplex = createWebSocketStream(ws, {});
      duplex.on('error', () => { try { ws.terminate(); } catch { /* gone */ } });
      resolve({ socket: duplex, leftover: Buffer.alloc(0) });
    });
    ws.once('unexpected-response', (_req, res) => {
      if (settled) return;
      settled = true;
      try { ws.terminate(); } catch { /* gone */ }
      reject(new Error(`relay: ws relay rejected handshake (${res.statusCode})`));
    });
    ws.once('error', (err) => {
      if (settled) return;
      settled = true;
      reject(err);
    });
  });
}

async function dialHttpConnect(entry, targetHost, targetPort, creds) {
  const socket = await openUpstreamSocket(entry);
  try {
    const reader = new SocketReader(socket);
    let head = `CONNECT ${targetHost}:${targetPort} HTTP/1.1${CRLF}`;
    head += `Host: ${targetHost}:${targetPort}${CRLF}`;
    if (creds?.username !== undefined) {
      head += `Proxy-Authorization: ${toBasicAuth(creds.username, creds.password ?? '')}${CRLF}`;
    }
    head += `Proxy-Connection: Keep-Alive${CRLF}${CRLF}`;
    socket.write(head);
    const responseHead = await reader.readUntil(HEAD_DELIM);
    const statusLine = responseHead.toString('latin1').split(CRLF)[0];
    const m = /^HTTP\/\d\.\d\s+(\d{3})/.exec(statusLine);
    if (!m) throw new Error(`relay: malformed upstream proxy response: ${statusLine}`);
    const status = parseInt(m[1], 10);
    if (status !== 200) throw new Error(`relay: upstream proxy CONNECT failed (${status})`);
    return { socket, leftover: reader.detach() };
  } catch (err) {
    socket.destroy();
    throw err;
  }
}

async function dialSocks5(entry, targetHost, targetPort, creds) {
  const socket = await openUpstreamSocket(entry);
  try {
    const reader = new SocketReader(socket);

    const hasCreds = creds?.username !== undefined;
    const methods = hasCreds ? [0x00, 0x02] : [0x00];
    socket.write(Buffer.from([0x05, methods.length, ...methods]));

    const selection = await reader.readBytes(2);
    if (selection[0] !== 0x05) throw new Error('relay: upstream is not a SOCKS5 proxy');
    if (selection[1] === 0xFF) throw new Error('relay: no acceptable SOCKS5 auth method offered by upstream');
    if (selection[1] === 0x02) {
      if (!hasCreds) throw new Error('relay: upstream requires SOCKS5 auth but no credentials configured');
      const user = Buffer.from(String(creds.username), 'utf8');
      const pass = Buffer.from(String(creds.password ?? ''), 'utf8');
      if (user.length > 255 || pass.length > 255) throw new Error('relay: SOCKS5 credentials too long');
      socket.write(Buffer.concat([
        Buffer.from([0x01, user.length]), user,
        Buffer.from([pass.length]), pass,
      ]));
      const authReply = await reader.readBytes(2);
      if (authReply[1] !== 0x00) throw new Error('relay: upstream rejected SOCKS5 credentials');
    }

    socket.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00]), socks5Destination(targetHost, targetPort)]));

    const reply = await reader.readBytes(4);
    if (reply[1] !== 0x00) throw new Error(`relay: upstream SOCKS5 CONNECT failed (rep=${reply[1]})`);
    // Drain the bound address so the stream is positioned at the tunnel payload.
    if (reply[3] === 0x01) await reader.readBytes(4 + 2);
    else if (reply[3] === 0x04) await reader.readBytes(16 + 2);
    else if (reply[3] === 0x03) {
      const len = await reader.readBytes(1);
      await reader.readBytes(len[0] + 2);
    }
    return { socket, leftover: reader.detach() };
  } catch (err) {
    socket.destroy();
    throw err;
  }
}

async function dialSocks4(entry, targetHost, targetPort, creds) {
  const socket = await openUpstreamSocket(entry);
  try {
    const reader = new SocketReader(socket);
    const portBuf = Buffer.alloc(2);
    portBuf.writeUInt16BE(targetPort, 0);
    const userId = creds?.username !== undefined ? Buffer.from(String(creds.username), 'utf8') : Buffer.alloc(0);

    let address;
    let hostnameTail = Buffer.alloc(0);
    if (net.isIPv4(targetHost)) {
      address = Buffer.from(targetHost.split('.').map(n => parseInt(n, 10)));
    } else {
      // SOCKS4a: signal "hostname follows" with a bogus 0.0.0.x address.
      address = Buffer.from([0x00, 0x00, 0x00, 0x01]);
      hostnameTail = Buffer.concat([Buffer.from(targetHost, 'utf8'), Buffer.from([0x00])]);
    }

    socket.write(Buffer.concat([
      Buffer.from([0x04, 0x01]), portBuf, address,
      userId, Buffer.from([0x00]), hostnameTail,
    ]));

    const reply = await reader.readBytes(8);
    if (reply[0] !== 0x00 || reply[1] !== 0x5A) {
      throw new Error(`relay: upstream SOCKS4 CONNECT failed (code=${reply[1]})`);
    }
    return { socket, leftover: reader.detach() };
  } catch (err) {
    socket.destroy();
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Request-header helpers (absolute-form HTTP through the relay)
// ---------------------------------------------------------------------------

function parseHeaders(lines) {
  const headers = Object.create(null);
  for (const line of lines) {
    if (!line) continue;
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    headers[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim();
  }
  return headers;
}

function buildHead(requestLine, headers) {
  let head = requestLine + CRLF;
  for (const [name, value] of headers) head += `${name}: ${value}${CRLF}`;
  return head + CRLF;
}

// ---------------------------------------------------------------------------
// Connection handling
// ---------------------------------------------------------------------------

function pipeBoth(a, b) {
  const destroyBoth = () => {
    a.destroy();
    b.destroy();
  };
  a.on('error', destroyBoth);
  b.on('error', destroyBoth);
  a.on('close', () => b.destroy());
  b.on('close', () => a.destroy());
  a.pipe(b);
  b.pipe(a);
}

function sendGatewayError(client, status = 502) {
  const text = status === 504 ? 'Gateway Timeout' : 'Bad Gateway';
  try {
    client.write(`HTTP/1.1 ${status} ${text}${CRLF}Content-Length: 0${CRLF}Connection: close${CRLF}${CRLF}`);
  } catch { /* client already gone */ }
  client.end();
}

async function handleClient(client, entry) {
  client.setNoDelay(true);
  const reader = new SocketReader(client);

  let rawHead;
  try {
    rawHead = await reader.readUntil(HEAD_DELIM);
  } catch {
    client.destroy();
    return;
  }

  const text = rawHead.toString('latin1');
  const lines = text.slice(0, -4).split(CRLF);
  const requestLine = lines[0] || '';
  const match = /^(\S+)\s+(\S+)\s+HTTP\/(\d\.\d)$/.exec(requestLine);
  if (!match) {
    client.write(`HTTP/1.1 400 Bad Request${CRLF}Content-Length: 0${CRLF}Connection: close${CRLF}${CRLF}`);
    client.end();
    return;
  }
  const method = match[1].toUpperCase();
  const target = match[2];
  const version = `HTTP/${match[3]}`;
  const headerLines = lines.slice(1);
  const headers = parseHeaders(headerLines);
  const clientAuth = parseBasicAuth(headers['proxy-authorization']);
  const creds = clientAuth || (entry.username !== undefined && entry.username !== null
    ? { username: entry.username, password: entry.password }
    : null);

  try {
    if (method === 'CONNECT') {
      const parsed = splitHostPort(target);
      if (!parsed) throw new Error(`relay: invalid CONNECT target ${target}`);
      const tunnel = await dialTunnel(entry, parsed.host, parsed.port, creds);
      client.write(`HTTP/1.1 200 Connection Established${CRLF}Proxy-Agent: camofox-relay${CRLF}${CRLF}`);
      const fromClient = reader.detach();
      if (fromClient.length) tunnel.socket.write(fromClient);
      if (tunnel.leftover.length) client.write(tunnel.leftover);
      pipeBoth(client, tunnel.socket);
      return;
    }

    // Absolute-form request (plain http:// through the proxy).
    let url;
    try {
      url = new URL(target);
    } catch {
      client.write(`HTTP/1.1 400 Bad Request${CRLF}Content-Length: 0${CRLF}Connection: close${CRLF}${CRLF}`);
      client.end();
      return;
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      client.write(`HTTP/1.1 400 Bad Request${CRLF}Content-Length: 0${CRLF}Connection: close${CRLF}${CRLF}`);
      client.end();
      return;
    }
    const targetPort = url.port ? parseInt(url.port, 10) : defaultPortForScheme(url.protocol.replace(/:$/, ''));
    const targetHost = url.hostname;

    if (entry.protocol === 'http' || entry.protocol === 'https') {
      // Forward the absolute-form request straight to the upstream HTTP proxy.
      const socket = await openUpstreamSocket(entry);
      const outHeaders = headerLines.map((line) => {
        const idx = line.indexOf(':');
        return idx === -1 ? line : [line.slice(0, idx).trim(), line.slice(idx + 1).trim()];
      }).filter((h) => Array.isArray(h));
      if (!headers['proxy-authorization'] && creds?.username !== undefined) {
        outHeaders.push(['Proxy-Authorization', toBasicAuth(creds.username, creds.password ?? '')]);
      }
      if (!headers['proxy-connection']) outHeaders.push(['Proxy-Connection', 'Keep-Alive']);
      socket.write(buildHead(`${method} ${target} ${version}`, outHeaders));
      const fromClient = reader.detach();
      if (fromClient.length) socket.write(fromClient);
      pipeBoth(client, socket);
      return;
    }

    // SOCKS upstream: open a tunnel, then speak origin-form to the origin.
    const tunnel = await dialTunnel(entry, targetHost, targetPort, creds);
    const originTarget = `${url.pathname}${url.search}`;
    const originHeaders = headerLines
      .filter((line) => {
        const idx = line.indexOf(':');
        if (idx === -1) return false;
        const name = line.slice(0, idx).trim().toLowerCase();
        return name !== 'proxy-authorization' && name !== 'proxy-connection';
      })
      .map((line) => {
        const idx = line.indexOf(':');
        return [line.slice(0, idx).trim(), line.slice(idx + 1).trim()];
      });
    tunnel.socket.write(buildHead(`${method} ${originTarget} ${version}`, originHeaders));
    const fromClient = reader.detach();
    if (fromClient.length) tunnel.socket.write(fromClient);
    if (tunnel.leftover.length) client.write(tunnel.leftover);
    pipeBoth(client, tunnel.socket);
  } catch {
    try { reader.detach(); } catch { /* not attached */ }
    sendGatewayError(client);
  }
}

// ---------------------------------------------------------------------------
// Relay manager
// ---------------------------------------------------------------------------

function routeKey(upstream) {
  return [
    upstream.protocol, upstream.host, upstream.port,
    upstream.username ?? '', upstream.password ?? '',
    upstream.proxyId ?? '', upstream.wsUrl ?? '',
  ].join('\u0000');
}

/**
 * Create the relay manager.
 *
 * options:
 *   enabled              boolean (default true)
 *   listenHost           string  (default 127.0.0.1)
 *   maxListeners         number  (default 256)
 *   idleTtlMs            number  (default 10 min)
 *   connectTimeoutMs     number  (default 30s)
 *   tlsRejectUnauthorized boolean (default true)
 */
export function createProxyRelay(options = {}) {
  const enabled = options.enabled !== false;
  const listenHost = options.listenHost || DEFAULT_LISTEN_HOST;
  const maxListeners = Number.isFinite(options.maxListeners) ? Math.max(1, options.maxListeners) : DEFAULT_MAX_LISTENERS;
  const idleTtlMs = Number.isFinite(options.idleTtlMs) ? Math.max(1000, options.idleTtlMs) : DEFAULT_IDLE_TTL_MS;
  const connectTimeoutMs = Number.isFinite(options.connectTimeoutMs) ? options.connectTimeoutMs : DEFAULT_CONNECT_TIMEOUT_MS;
  const tlsRejectUnauthorized = options.tlsRejectUnauthorized !== false;
  // Bearer the ws relay (BookNetwork Worker /relay) validates against a camofox
  // instance access_key. Only used by ws/wss upstreams; ignored otherwise.
  const accessKey = options.accessKey || null;

  const routes = new Map();
  let listenerCount = 0;
  let createdCount = 0;

  function createListener(entry) {
    const server = net.createServer((socket) => {
      entry.connections++;
      entry.lastUsed = Date.now();
      socket.on('close', () => {
        entry.connections = Math.max(0, entry.connections - 1);
        entry.lastUsed = Date.now();
      });
      handleClient(socket, entry).catch(() => {
        socket.destroy();
      });
    });
    return new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, listenHost, () => {
        server.off('error', reject);
        server.on('error', () => { /* keep a listener for post-ready errors */ });
        resolve(server);
      });
    });
  }

  function closeEntry(entry) {
    if (entry.closed) return;
    entry.closed = true;
    routes.delete(entry.key);
    listenerCount = Math.max(0, listenerCount - 1);
    try { entry.server.close(); } catch { /* already closed */ }
  }

  function enforceCap() {
    if (routes.size <= maxListeners) return;
    const idle = [...routes.values()]
      .filter((e) => e.connections === 0)
      .sort((a, b) => a.lastUsed - b.lastUsed);
    for (const entry of idle) {
      if (routes.size <= maxListeners) break;
      closeEntry(entry);
    }
  }

  async function acquire(upstream) {
    const key = routeKey(upstream);
    const existing = routes.get(key);
    if (existing && !existing.closed) {
      existing.lastUsed = Date.now();
      return existing;
    }
    const entry = {
      key,
      protocol: upstream.protocol,
      host: upstream.host,
      port: upstream.port,
      username: upstream.username,
      password: upstream.password,
      // ws/wss relay only:
      wsUrl: upstream.wsUrl,
      proxyId: upstream.proxyId,
      accessKey,
      tlsRejectUnauthorized,
      connectTimeoutMs,
      connections: 0,
      lastUsed: Date.now(),
      closed: false,
      server: null,
      localPort: 0,
    };
    entry.server = await createListener(entry);
    const address = entry.server.address();
    entry.localPort = typeof address === 'object' && address ? address.port : 0;
    routes.set(key, entry);
    listenerCount++;
    createdCount++;
    enforceCap();
    return entry;
  }

  const evictionTimer = setInterval(() => {
    const now = Date.now();
    for (const entry of [...routes.values()]) {
      if (entry.connections === 0 && now - entry.lastUsed >= idleTtlMs) closeEntry(entry);
    }
  }, Math.min(idleTtlMs, 60 * 1000));
  if (evictionTimer.unref) evictionTimer.unref();

  return {
    enabled,

    /**
     * Map an upstream Playwright proxy spec to its local relay endpoint.
     * Credentials are dropped from the returned spec -- the relay owns them,
     * which is what lets the browser stay on a plain unauthenticated proxy.
     * Returns the input unchanged when relaying is disabled or unparsable.
     */
    async mapProxy(proxy) {
      if (!enabled || !proxy || !proxy.server) return proxy;
      const upstream = parseUpstreamServer(proxy.server);
      if (!upstream) return proxy;
      const isWs = upstream.protocol === 'ws' || upstream.protocol === 'wss';
      const entry = await acquire({
        ...upstream,
        username: proxy.username,
        password: proxy.password,
        // ws/wss relay: keep the full endpoint + which residential proxy to use.
        wsUrl: isWs ? proxy.server : undefined,
        proxyId: isWs ? proxy.proxyId : undefined,
      });
      return {
        ...proxy,
        server: `http://${listenHost}:${entry.localPort}`,
        username: undefined,
        password: undefined,
        proxyId: undefined,
      };
    },

    stats() {
      return {
        enabled,
        listeners: listenerCount,
        created: createdCount,
        max: maxListeners,
        ports: [...routes.values()].map((e) => ({
          port: e.localPort,
          protocol: e.protocol,
          upstream: `${e.host}:${e.port}`,
          connections: e.connections,
        })),
      };
    },

    close() {
      clearInterval(evictionTimer);
      for (const entry of [...routes.values()]) closeEntry(entry);
    },
  };
}
