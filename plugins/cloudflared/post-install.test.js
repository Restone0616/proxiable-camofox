import { createHash } from 'node:crypto';
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

// Run the hook by name from its own directory. A file:// pathname is not a
// usable argument for sh on Windows, where it comes back as "/E:/...".
const pluginDir = dirname(fileURLToPath(import.meta.url));

function makeHarness() {
  const dir = mkdtempSync(join(tmpdir(), 'camofox-cloudflared-'));
  const fixture = join(dir, 'fixture');
  const calls = join(dir, 'curl-calls');
  const installPath = join(dir, 'cloudflared');

  writeFileSync(fixture, '#!/bin/sh\necho cloudflared fixture\n');
  writeFileSync(join(dir, 'curl'), `#!/bin/sh
set -eu
printf '%s\\n' "$@" > "$CURL_CALLS"
cp "$CLOUDFLARED_FIXTURE" "$4"
`);
  writeFileSync(join(dir, 'sha256sum'), `#!/bin/sh
set -eu
[ "$1" = '-c' ] && [ "$2" = '-' ]
read -r expected path
actual=$(shasum -a 256 "$path" | awk '{print $1}')
[ "$expected" = "$actual" ]
`);
  // dpkg must be absent from this PATH so the script's architecture detection
  // falls through to the CLOUDFLARED_ARCH override the tests set.
  chmodSync(join(dir, 'curl'), 0o755);
  chmodSync(join(dir, 'sha256sum'), 0o755);

  return {
    dir,
    calls,
    fixture,
    installPath,
    digest() {
      return createHash('sha256').update(readFileSync(fixture)).digest('hex');
    },
    run(overrides = {}) {
      return execFileSync('sh', ['post-install.sh'], {
        cwd: pluginDir,
        env: {
          ...process.env,
          PATH: `${dir}:${process.env.PATH}`,
          CURL_CALLS: calls,
          CLOUDFLARED_FIXTURE: fixture,
          CLOUDFLARED_INSTALL_PATH: installPath,
          CLOUDFLARED_VERSION: 'test-release',
          ...overrides,
        },
        stdio: 'pipe',
      });
    },
  };
}

describe('cloudflared post-install hook pinning', () => {
  it('pins a default version and a checksum per architecture', () => {
    // The pinned values are the contract with Cloudflare's published checksums;
    // an unpinned download would install whatever is current, unverified.
    const source = readFileSync(join(pluginDir, 'post-install.sh'), 'utf8');
    expect(source).toMatch(/CLOUDFLARED_VERSION:=\d{4}\.\d+\.\d+/);
    expect(source.match(/default_sha=[0-9a-f]{64}/g)).toHaveLength(2);
    expect(source).toContain('sha256sum -c -');
  });
});

// The harness below shadows curl and sha256sum by prepending a directory to
// PATH, which only works where PATH is POSIX-shaped. On Windows the value Node
// hands to Git Bash is ';'-separated, the stubs are never found, and the hook
// reaches for the real network. CI runs these on Linux.
const describePosix = process.platform === 'win32' ? describe.skip : describe;

describePosix('cloudflared post-install hook', () => {
  let harness;

  beforeEach(() => {
    harness = makeHarness();
  });

  afterEach(() => {
    rmSync(harness.dir, { recursive: true, force: true });
  });

  it('downloads the amd64 asset, verifies it, and makes it executable', () => {
    harness.run({ CLOUDFLARED_ARCH: 'amd64', CLOUDFLARED_SHA256: harness.digest() });

    expect(readFileSync(harness.installPath)).toEqual(readFileSync(harness.fixture));
    expect(statSync(harness.installPath).mode & 0o111).not.toBe(0);
    expect(readFileSync(harness.calls, 'utf8')).toBe([
      '-fL',
      'https://github.com/cloudflare/cloudflared/releases/download/test-release/cloudflared-linux-amd64',
      '-o',
      harness.installPath,
      '',
    ].join('\n'));
  });

  it('picks the arm64 asset for an arm64 host', () => {
    harness.run({ CLOUDFLARED_ARCH: 'arm64', CLOUDFLARED_SHA256: harness.digest() });
    expect(readFileSync(harness.calls, 'utf8')).toContain('cloudflared-linux-arm64');
  });

  it('accepts the uname spellings of both architectures', () => {
    harness.run({ CLOUDFLARED_ARCH: 'x86_64', CLOUDFLARED_SHA256: harness.digest() });
    expect(readFileSync(harness.calls, 'utf8')).toContain('cloudflared-linux-amd64');

    harness.run({ CLOUDFLARED_ARCH: 'aarch64', CLOUDFLARED_SHA256: harness.digest() });
    expect(readFileSync(harness.calls, 'utf8')).toContain('cloudflared-linux-arm64');
  });

  it('fails before chmod when the downloaded binary digest differs', () => {
    expect(() => harness.run({
      CLOUDFLARED_ARCH: 'amd64',
      CLOUDFLARED_SHA256: '0'.repeat(64),
    })).toThrow();

    expect(statSync(harness.installPath).mode & 0o111).toBe(0);
  });

  it('refuses an architecture it has no pinned checksum for', () => {
    expect(() => harness.run({ CLOUDFLARED_ARCH: 'mips64el' })).toThrow();
  });
});
