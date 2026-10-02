import { describe, it, expect, vi } from 'vitest';

import { createGuardedFetcher, GuardedFetchError } from '../../src/index.js';
import { isPublicIpAddress } from '../../src/http/ip-address.js';
import type { Fetcher } from '../../src/trust/Fetcher.js';

function randomHost(): string {
    return `h${crypto.randomUUID().slice(0, 8)}.example.eu`;
}

function randomBytes(n: number): Uint8Array {
    const out = new Uint8Array(n);
    crypto.getRandomValues(out.subarray(0, Math.min(n, 65536)));
    return out;
}

/** Public, routable documentation-free address (Cloudflare anycast). */
const PUBLIC_V4 = '104.16.0.1';

const publicLookup = vi.fn(async () => [PUBLIC_V4]);

async function rejection(p: Promise<unknown>): Promise<GuardedFetchError> {
    try {
        await p;
    } catch (err) {
        expect(err).toBeInstanceOf(GuardedFetchError);
        return err as GuardedFetchError;
    }
    throw new Error('expected rejection');
}

describe('createGuardedFetcher', () => {
    it('passes a public HTTPS request through and returns the body', async () => {
        const body = randomBytes(64);
        const base: Fetcher = vi.fn(async () => new Response(body, { status: 200 }));
        const fetcher = createGuardedFetcher({ fetch: base, lookup: publicLookup });
        const res = await fetcher(`https://${randomHost()}/x`);
        expect(res.status).toBe(200);
        expect(new Uint8Array(await res.arrayBuffer())).toEqual(body);
        expect((base as ReturnType<typeof vi.fn>).mock.calls[0][1]).toMatchObject({ redirect: 'manual' });
    });

    it('rejects http: by default (draft-19: HTTPS only)', async () => {
        const base: Fetcher = vi.fn();
        const fetcher = createGuardedFetcher({ fetch: base, lookup: publicLookup });
        const err = await rejection(fetcher(`http://${randomHost()}/`));
        expect(err.reason).toBe('insecure_scheme');
        expect(base).not.toHaveBeenCalled();
    });

    it('allows http: only with allowHttp', async () => {
        const base: Fetcher = vi.fn(async () => new Response('ok'));
        const fetcher = createGuardedFetcher({ fetch: base, lookup: publicLookup, allowHttp: true });
        expect((await fetcher(`http://${randomHost()}/`)).status).toBe(200);
    });

    it('rejects non-http schemes even with allowHttp', async () => {
        const fetcher = createGuardedFetcher({ fetch: vi.fn(), lookup: publicLookup, allowHttp: true });
        expect((await rejection(fetcher('file:///etc/passwd'))).reason).toBe('insecure_scheme');
    });

    it.each([
        'https://127.0.0.1/',
        'https://169.254.169.254/latest/meta-data/',
        'https://10.1.2.3/',
        'https://[::1]/',
        'https://[::ffff:169.254.169.254]/',
        'https://[fe80::1]/',
        'https://[fd00:ec2::254]/',
        'https://localhost/',
        'https://foo.localhost/',
        'https://2130706433/',
    ])('rejects literal private / loopback / metadata target %s', async (url) => {
        const base: Fetcher = vi.fn();
        const fetcher = createGuardedFetcher({ fetch: base, lookup: publicLookup });
        expect((await rejection(fetcher(url))).reason).toBe('private_address');
        expect(base).not.toHaveBeenCalled();
    });

    it('rejects a hostname that resolves to a private address (any record)', async () => {
        const base: Fetcher = vi.fn();
        const lookup = vi.fn(async () => [PUBLIC_V4, '192.168.0.10']);
        const fetcher = createGuardedFetcher({ fetch: base, lookup });
        expect((await rejection(fetcher(`https://${randomHost()}/`))).reason).toBe('private_address');
        expect(base).not.toHaveBeenCalled();
    });

    it('allows private targets only with allowPrivateNetworks', async () => {
        const base: Fetcher = vi.fn(async () => new Response('ok'));
        const fetcher = createGuardedFetcher({ fetch: base, lookup: publicLookup, allowPrivateNetworks: true });
        expect((await fetcher('https://10.0.0.1/')).status).toBe(200);
    });

    it('reports DNS failures as dns_resolution_failed', async () => {
        const lookup = vi.fn(async () => {
            throw new Error('ENOTFOUND');
        });
        const fetcher = createGuardedFetcher({ fetch: vi.fn(), lookup });
        expect((await rejection(fetcher(`https://${randomHost()}/`))).reason).toBe('dns_resolution_failed');
    });

    it('fails closed when the resolver returns no addresses at all', async () => {
        // An empty answer is not evidence that the host is public. Treating it
        // as "nothing blocked" would let any resolver quirk — or a custom
        // lookup that swallows errors — wave every hostname through.
        const base = vi.fn<Fetcher>();
        const fetcher = createGuardedFetcher({ fetch: base, lookup: vi.fn(async () => []) });
        expect((await rejection(fetcher(`https://${randomHost()}/`))).reason).toBe('dns_resolution_failed');
        expect(base).not.toHaveBeenCalled();
    });

    it('fails closed when a redirect target resolves to no addresses', async () => {
        const first = randomHost();
        const second = randomHost();
        const base: Fetcher = vi.fn(async () =>
            new Response(null, { status: 302, headers: { location: `https://${second}/` } })
        );
        const lookup = vi.fn(async (host: string) => (host === first ? [PUBLIC_V4] : []));
        const fetcher = createGuardedFetcher({ fetch: base, lookup });
        expect((await rejection(fetcher(`https://${first}/`))).reason).toBe('dns_resolution_failed');
        expect(base).toHaveBeenCalledTimes(1);
    });

    it('follows a redirect to a public target and re-validates it', async () => {
        const first = randomHost();
        const second = randomHost();
        const base: Fetcher = vi.fn(async (url: string) =>
            url.includes(first)
                ? new Response(null, { status: 302, headers: { location: `https://${second}/final` } })
                : new Response('final'),
        );
        const lookup = vi.fn(async () => [PUBLIC_V4]);
        const fetcher = createGuardedFetcher({ fetch: base, lookup });
        const res = await fetcher(`https://${first}/start`);
        expect(await res.text()).toBe('final');
        expect(lookup).toHaveBeenCalledWith(second);
    });

    it('rejects a redirect whose target resolves to a private address', async () => {
        const first = randomHost();
        const evil = randomHost();
        const base: Fetcher = vi.fn(
            async () => new Response(null, { status: 301, headers: { location: `https://${evil}/` } }),
        );
        const lookup = vi.fn(async (host: string) => (host === evil ? ['169.254.169.254'] : [PUBLIC_V4]));
        const fetcher = createGuardedFetcher({ fetch: base, lookup });
        expect((await rejection(fetcher(`https://${first}/`))).reason).toBe('private_address');
        expect(base).toHaveBeenCalledTimes(1);
    });

    it('rejects a redirect to a literal private IP', async () => {
        const base: Fetcher = vi.fn(
            async () => new Response(null, { status: 307, headers: { location: 'https://127.0.0.1:8080/admin' } }),
        );
        const fetcher = createGuardedFetcher({ fetch: base, lookup: publicLookup });
        expect((await rejection(fetcher(`https://${randomHost()}/`))).reason).toBe('private_address');
    });

    it('rejects an https -> http downgrade even with allowHttp', async () => {
        const base: Fetcher = vi.fn(
            async () => new Response(null, { status: 302, headers: { location: `http://${randomHost()}/` } }),
        );
        const fetcher = createGuardedFetcher({ fetch: base, lookup: publicLookup, allowHttp: true });
        expect((await rejection(fetcher(`https://${randomHost()}/`))).reason).toBe('insecure_scheme');
    });

    it('stops after maxRedirects', async () => {
        const base: Fetcher = vi.fn(
            async () => new Response(null, { status: 302, headers: { location: `https://${randomHost()}/` } }),
        );
        const maxRedirects = 1 + Math.floor(Math.random() * 3);
        const fetcher = createGuardedFetcher({ fetch: base, lookup: publicLookup, maxRedirects });
        expect((await rejection(fetcher(`https://${randomHost()}/`))).reason).toBe('too_many_redirects');
        expect(base).toHaveBeenCalledTimes(maxRedirects + 1);
    });

    it('rejects a redirect without a Location header', async () => {
        const base: Fetcher = vi.fn(async () => new Response(null, { status: 302 }));
        const fetcher = createGuardedFetcher({ fetch: base, lookup: publicLookup });
        expect((await rejection(fetcher(`https://${randomHost()}/`))).reason).toBe('invalid_redirect');
    });

    it('turns a POST into a body-less GET on 303', async () => {
        const second = randomHost();
        const base = vi.fn(async (url: string, _init?: RequestInit) =>
            url.includes(second)
                ? new Response('ok')
                : new Response(null, { status: 303, headers: { location: `https://${second}/` } }),
        );
        const fetcher = createGuardedFetcher({ fetch: base, lookup: publicLookup });
        await fetcher(`https://${randomHost()}/`, { method: 'POST', body: randomBytes(8) as Uint8Array<ArrayBuffer> });
        expect(base.mock.calls[1][1]).toMatchObject({ method: 'GET', body: undefined });
    });

    it('rejects a response whose Content-Length exceeds maxResponseBytes', async () => {
        const max = 100 + Math.floor(Math.random() * 100);
        const base: Fetcher = vi.fn(
            async () => new Response(randomBytes(max + 1), { headers: { 'content-length': String(max + 1) } }),
        );
        const fetcher = createGuardedFetcher({ fetch: base, lookup: publicLookup, maxResponseBytes: max });
        expect((await rejection(fetcher(`https://${randomHost()}/`))).reason).toBe('response_too_large');
    });

    it('enforces maxResponseBytes while streaming when Content-Length is absent', async () => {
        const max = 1024;
        let pulled = 0;
        const stream = new ReadableStream<Uint8Array>({
            pull(controller) {
                pulled++;
                controller.enqueue(randomBytes(512));
                if (pulled > 1000) controller.close();
            },
        });
        const base: Fetcher = vi.fn(async () => new Response(stream));
        const fetcher = createGuardedFetcher({ fetch: base, lookup: publicLookup, maxResponseBytes: max });
        expect((await rejection(fetcher(`https://${randomHost()}/`))).reason).toBe('response_too_large');
        // Stopped early instead of buffering the whole (unbounded) stream.
        expect(pulled).toBeLessThan(10);
    });

    it('times out a request that never answers', async () => {
        const base: Fetcher = vi.fn(() => new Promise<Response>(() => {}));
        const fetcher = createGuardedFetcher({ fetch: base, lookup: publicLookup, timeoutMs: 20 });
        expect((await rejection(fetcher(`https://${randomHost()}/`))).reason).toBe('timeout');
    });

    it('times out a body that stalls mid-stream', async () => {
        const stream = new ReadableStream<Uint8Array>({
            start(controller) {
                controller.enqueue(randomBytes(16));
            },
        });
        const base: Fetcher = vi.fn(async () => new Response(stream));
        const fetcher = createGuardedFetcher({ fetch: base, lookup: publicLookup, timeoutMs: 30 });
        expect((await rejection(fetcher(`https://${randomHost()}/`))).reason).toBe('timeout');
    });

    it('propagates a caller abort', async () => {
        const controller = new AbortController();
        const base: Fetcher = vi.fn(() => new Promise<Response>(() => {}));
        const fetcher = createGuardedFetcher({ fetch: base, lookup: publicLookup });
        const p = fetcher(`https://${randomHost()}/`, { signal: controller.signal });
        controller.abort(new Error('caller gave up'));
        await expect(p).rejects.toThrow('caller gave up');
    });

    it('rejects an invalid URL', async () => {
        const fetcher = createGuardedFetcher({ fetch: vi.fn(), lookup: publicLookup });
        expect((await rejection(fetcher('not a url'))).reason).toBe('invalid_url');
    });
});

describe('isPublicIpAddress', () => {
    it.each([
        '0.0.0.0',
        '10.0.0.1',
        '100.64.0.1',
        '127.0.0.1',
        '169.254.169.254',
        '172.16.0.1',
        '172.31.255.255',
        '192.168.1.1',
        '198.18.0.1',
        '224.0.0.1',
        '255.255.255.255',
        '::',
        '::1',
        '::ffff:127.0.0.1',
        '::ffff:7f00:1',
        '::127.0.0.1',
        '64:ff9b::a9fe:a9fe',
        '2002:a9fe:a9fe::1',
        'fc00::1',
        'fd00:ec2::254',
        'fe80::1%eth0',
        'ff02::1',
        '2001:db8::1',
    ])('classifies %s as non-public', (ip) => {
        expect(isPublicIpAddress(ip)).toBe(false);
    });

    it.each([PUBLIC_V4, '8.8.8.8', '172.32.0.1', '2a00:1450:4001:80b::200e', '::ffff:8.8.8.8'])(
        'classifies %s as public',
        (ip) => {
            expect(isPublicIpAddress(ip)).toBe(true);
        },
    );

    it('treats unparseable input as non-public (fail closed)', () => {
        expect(isPublicIpAddress('999.1.1.1')).toBe(false);
        expect(isPublicIpAddress('1:2:3')).toBe(false);
    });
});
