import { randomInt } from 'node:crypto';

import * as jose from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';

import { StatusListError } from '../../src/errors.js';
import { createGuardedFetcher } from '../../src/http/guarded-fetch.js';
import { StatusListResolver, type StatusListResolverOptions } from '../../src/status/StatusListResolver.js';
import { StaticTrustStore } from '../../src/trust/TrustStore.js';

import {
    buildStatusListJwt,
    createClock,
    createStatusListSigner,
    createStubFetcher,
    randomStatuses,
    randomStatusUri,
    rootB64,
    type StatusListSigner,
} from './helpers.js';

let signer: StatusListSigner;
let otherSigner: StatusListSigner;

beforeAll(async () => {
    signer = await createStatusListSigner();
    otherSigner = await createStatusListSigner();
});

async function expectReason(p: Promise<unknown>, reason: string): Promise<void> {
    await expect(p).rejects.toSatisfy((err: unknown) => err instanceof StatusListError && err.reason === reason);
}

/** A resolver serving one token at a fresh URI. */
async function setup(
    tokenOpts: Partial<Parameters<typeof buildStatusListJwt>[0]> = {},
    resolverOpts: Partial<StatusListResolverOptions> = {},
) {
    const uri = tokenOpts.uri ?? randomStatusUri();
    const statuses = tokenOpts.statuses ?? randomStatuses(2, 4 * randomInt(1, 16));
    const token = await buildStatusListJwt({ signer, uri, bits: 2, statuses, ...tokenOpts });
    const stub = createStubFetcher({ [uri]: { body: token } });
    const resolver = new StatusListResolver({
        trustStore: signer.trustStore,
        fetcher: stub.fetcher,
        ...resolverOpts,
    });
    return { uri, statuses, token, stub, resolver };
}

describe('StatusListResolver — happy path', () => {
    it('resolves every index of a verified list and maps the status type', async () => {
        const { uri, statuses, resolver } = await setup();
        for (let idx = 0; idx < statuses.length; idx++) {
            const lookup = await resolver.resolve({ uri, idx });
            expect(lookup.value).toBe(statuses[idx]);
            expect(lookup.status).toBe(['valid', 'invalid', 'suspended', 'unknown'][statuses[idx]]);
            expect(lookup.uri).toBe(uri);
            expect(lookup.idx).toBe(idx);
        }
    });

    it('sends Accept: application/statuslist+jwt with a GET', async () => {
        const { uri, stub, resolver } = await setup();
        await resolver.resolve({ uri, idx: 0 });
        expect(stub.calls).toHaveLength(1);
        expect(stub.calls[0].init?.method).toBe('GET');
        expect(new Headers(stub.calls[0].init?.headers).get('accept')).toBe('application/statuslist+jwt');
    });

    it('validates a signer under an intermediate carried in x5c', async () => {
        const chained = await createStatusListSigner({ intermediate: true });
        const uri = randomStatusUri();
        const token = await buildStatusListJwt({ signer: chained, uri, bits: 1, statuses: [0, 1, 0, 0, 0, 0, 0, 0] });
        const resolver = new StatusListResolver({
            trustStore: chained.trustStore,
            fetcher: createStubFetcher({ [uri]: { body: token } }).fetcher,
        });
        await expect(resolver.resolve({ uri, idx: 1 })).resolves.toMatchObject({ status: 'invalid', value: 1 });
        const list = await resolver.getStatusList(uri);
        expect(list.trust.chain).toHaveLength(3);
    });

    it('accepts the application/ prefixed typ form', async () => {
        const { uri, resolver } = await setup({ header: { typ: 'application/statuslist+jwt' } });
        await expect(resolver.resolve({ uri, idx: 0 })).resolves.toBeDefined();
    });

    it('requires a trustStore', () => {
        expect(() => new StatusListResolver({} as StatusListResolverOptions)).toThrow(StatusListError);
    });

    it('uses the HTTPS-only guarded fetcher by default', async () => {
        const resolver = new StatusListResolver({ trustStore: signer.trustStore });
        const uri = `http://status.example.eu/${randomInt(1, 1e6)}`;
        await expect(resolver.resolve({ uri, idx: 0 })).rejects.toSatisfy(
            (err: unknown) =>
                err instanceof StatusListError &&
                err.reason === 'fetch_failed' &&
                (err.cause as { reason?: string }).reason === 'insecure_scheme',
        );
    });
});

describe('StatusListResolver — token validation failures', () => {
    it('wrong typ', async () => {
        const { uri, resolver } = await setup({ header: { typ: 'JWT' } });
        await expectReason(resolver.resolve({ uri, idx: 0 }), 'invalid_token');
    });

    it('missing typ', async () => {
        const { uri, resolver } = await setup({ header: { typ: undefined } });
        await expectReason(resolver.resolve({ uri, idx: 0 }), 'invalid_token');
    });

    it('disallowed alg', async () => {
        const uri = randomStatusUri();
        const secret = crypto.getRandomValues(new Uint8Array(32));
        const token = await new jose.CompactSign(new TextEncoder().encode(JSON.stringify({ sub: uri })))
            .setProtectedHeader({ alg: 'HS256', typ: 'statuslist+jwt', x5c: signer.x5c })
            .sign(secret);
        const resolver = new StatusListResolver({
            trustStore: signer.trustStore,
            fetcher: createStubFetcher({ [uri]: { body: token } }).fetcher,
        });
        await expectReason(resolver.resolve({ uri, idx: 0 }), 'invalid_token');
    });

    it('bad signature (payload tampered after signing)', async () => {
        const { uri, token } = await setup();
        const [h, , s] = token.split('.');
        const forged = jose.base64url.encode(
            JSON.stringify({ sub: uri, iat: Math.floor(Date.now() / 1000), status_list: { bits: 1, lst: 'eNpjAAAAAQAB' } }),
        );
        const resolver = new StatusListResolver({
            trustStore: signer.trustStore,
            fetcher: createStubFetcher({ [uri]: { body: `${h}.${forged}.${s}` } }).fetcher,
        });
        await expectReason(resolver.resolve({ uri, idx: 0 }), 'signature_invalid');
    });

    it('signature by a key other than x5c[0]', async () => {
        const { uri, resolver, stub } = await setup();
        stub.set(uri, {
            body: await buildStatusListJwt({ signer: { ...otherSigner, x5c: signer.x5c }, uri }),
        });
        await expectReason(resolver.resolve({ uri, idx: 0 }), 'signature_invalid');
    });

    it('signer that does not chain to the status-list anchors', async () => {
        const uri = randomStatusUri();
        const resolver = new StatusListResolver({
            trustStore: signer.trustStore,
            fetcher: createStubFetcher({ [uri]: { body: await buildStatusListJwt({ signer: otherSigner, uri }) } })
                .fetcher,
        });
        await expectReason(resolver.resolve({ uri, idx: 0 }), 'untrusted_signer');
    });

    it('trust anchor included in x5c', async () => {
        const { uri, resolver } = await setup({ header: { x5c: [...signer.x5c, rootB64(signer)] } });
        await expectReason(resolver.resolve({ uri, idx: 0 }), 'untrusted_signer');
    });

    it('pinned signer (x5c[0] is the anchor) is refused unless acceptPinnedSigner', async () => {
        const uri = randomStatusUri();
        const token = await buildStatusListJwt({ signer, uri });
        const pinnedStore = new StaticTrustStore([signer.leafDer]);
        const fetcher = createStubFetcher({ [uri]: { body: token } }).fetcher;
        await expectReason(
            new StatusListResolver({ trustStore: pinnedStore, fetcher }).resolve({ uri, idx: 0 }),
            'untrusted_signer',
        );
        await expect(
            new StatusListResolver({ trustStore: pinnedStore, fetcher, acceptPinnedSigner: true }).resolve({ uri, idx: 0 }),
        ).resolves.toBeDefined();
    });

    it('missing x5c', async () => {
        const { uri, resolver } = await setup({ header: { x5c: undefined, kid: 'k1' } });
        await expectReason(resolver.resolve({ uri, idx: 0 }), 'invalid_token');
    });

    it('sub does not match the referenced uri', async () => {
        const { uri, resolver } = await setup({ claims: { sub: randomStatusUri() } });
        await expectReason(resolver.resolve({ uri, idx: 0 }), 'subject_mismatch');
    });

    it('sub missing', async () => {
        const { uri, resolver } = await setup({ claims: { sub: undefined } });
        await expectReason(resolver.resolve({ uri, idx: 0 }), 'invalid_token');
    });

    it('expired (exp passed beyond skew)', async () => {
        const now = Math.floor(Date.now() / 1000);
        const { uri, resolver } = await setup({ claims: { iat: now - 7200, exp: now - randomInt(61, 3600) } });
        await expectReason(resolver.resolve({ uri, idx: 0 }), 'expired');
    });

    it('exp within the skew tolerance is still accepted', async () => {
        const now = Math.floor(Date.now() / 1000);
        const { uri, resolver } = await setup({ claims: { exp: now - 5 } });
        await expect(resolver.resolve({ uri, idx: 0 })).resolves.toBeDefined();
    });

    it('iat missing or in the future', async () => {
        const now = Math.floor(Date.now() / 1000);
        const missing = await setup({ claims: { iat: undefined } });
        await expectReason(missing.resolver.resolve({ uri: missing.uri, idx: 0 }), 'invalid_token');
        const future = await setup({ claims: { iat: now + randomInt(120, 3600) } });
        await expectReason(future.resolver.resolve({ uri: future.uri, idx: 0 }), 'not_fresh');
    });

    it('iat older than maxListAgeSeconds', async () => {
        const now = Math.floor(Date.now() / 1000);
        const maxListAgeSeconds = randomInt(600, 3600);
        const { uri, resolver } = await setup(
            { claims: { iat: now - maxListAgeSeconds - 120 } },
            { maxListAgeSeconds },
        );
        await expectReason(resolver.resolve({ uri, idx: 0 }), 'not_fresh');
    });

    it('nbf in the future', async () => {
        const now = Math.floor(Date.now() / 1000);
        const { uri, resolver } = await setup({ claims: { nbf: now + 600 } });
        await expectReason(resolver.resolve({ uri, idx: 0 }), 'not_fresh');
    });

    it.each([0, -5, '600'])('ttl %s is not a positive number', async (ttl) => {
        const { uri, resolver } = await setup({ claims: { ttl } });
        await expectReason(resolver.resolve({ uri, idx: 0 }), 'invalid_token');
    });

    it('malformed status_list', async () => {
        const { uri, resolver } = await setup({ claims: { status_list: { bits: 3, lst: 'eNrbuRgAAhcBXQ' } } });
        await expectReason(resolver.resolve({ uri, idx: 0 }), 'malformed_status_list');
    });

    it('index out of range of an authentic list', async () => {
        const { uri, statuses, resolver } = await setup();
        await expectReason(resolver.resolve({ uri, idx: statuses.length + randomInt(0, 100) }), 'index_out_of_range');
    });

    it.each([
        { uri: 'not a uri', idx: 0 },
        { uri: 'https://status.example.eu/x', idx: -1 },
        { uri: 'https://status.example.eu/x', idx: '0' },
        { idx: 0 },
    ])('invalid reference %j', async (ref) => {
        const resolver = new StatusListResolver({ trustStore: signer.trustStore, fetcher: createStubFetcher().fetcher });
        await expectReason(resolver.resolve(ref as never), 'invalid_reference');
    });

    it('HTTP error, transport error and non-JWS body are fetch_failed / invalid_token', async () => {
        const uri = randomStatusUri();
        const stub = createStubFetcher({ [uri]: { status: 503, body: 'down' } });
        const resolver = new StatusListResolver({ trustStore: signer.trustStore, fetcher: stub.fetcher });
        await expectReason(resolver.resolve({ uri, idx: 0 }), 'fetch_failed');
        stub.set(uri, new TypeError('fetch failed'));
        await expectReason(resolver.resolve({ uri, idx: 0 }), 'fetch_failed');
        stub.set(uri, { body: '<html>hello</html>' });
        await expectReason(resolver.resolve({ uri, idx: 0 }), 'invalid_token');
    });

    it('refuses private targets through the guarded fetcher', async () => {
        const resolver = new StatusListResolver({
            trustStore: signer.trustStore,
            fetcher: createGuardedFetcher({ fetch: createStubFetcher().fetcher }),
        });
        await expectReason(resolver.resolve({ uri: 'https://127.0.0.1/list', idx: 0 }), 'fetch_failed');
    });
});

describe('StatusListResolver — caching', () => {
    it('serves from cache within ttl and refetches after it', async () => {
        const clock = createClock();
        const ttl = randomInt(120, 900);
        const { uri, stub, resolver } = await setup(
            { claims: { ttl }, nowSeconds: Math.floor(clock.now().getTime() / 1000) },
            { clock: clock.now },
        );
        expect((await resolver.resolve({ uri, idx: 0 })).fromCache).toBe(false);
        clock.advance(ttl - 1);
        expect((await resolver.resolve({ uri, idx: 1 })).fromCache).toBe(true);
        expect(stub.calls).toHaveLength(1);
        clock.advance(2);
        expect((await resolver.resolve({ uri, idx: 0 })).fromCache).toBe(false);
        expect(stub.calls).toHaveLength(2);
    });

    it('never caches past exp, even with a longer ttl', async () => {
        const clock = createClock();
        const nowS = Math.floor(clock.now().getTime() / 1000);
        const { uri, stub, resolver } = await setup(
            { claims: { ttl: 3600, exp: nowS + 300 }, nowSeconds: nowS },
            { clock: clock.now },
        );
        const lookup = await resolver.resolve({ uri, idx: 0 });
        expect(lookup.list.cacheUntil.getTime()).toBe((nowS + 300) * 1000);
        clock.advance(300 + 61); // past exp plus the 60 s skew tolerance
        // The cached copy is gone; the stubbed token is now itself expired.
        await expectReason(resolver.resolve({ uri, idx: 0 }), 'expired');
        expect(stub.calls).toHaveLength(2);
    });

    it('clamps ttl to [minTtlSeconds, maxTtlSeconds] and uses defaultTtlSeconds when absent', async () => {
        const clock = createClock();
        const nowS = Math.floor(clock.now().getTime() / 1000);
        const base = { nowSeconds: nowS, claims: { exp: nowS + 10 * 86_400 } };
        const lo = await setup({ ...base, claims: { ...base.claims, ttl: 1 } }, { clock: clock.now, minTtlSeconds: 90 });
        expect((await lo.resolver.resolve({ uri: lo.uri, idx: 0 })).list.cacheUntil.getTime() - clock.now().getTime()).toBe(
            90_000,
        );
        const hi = await setup(
            { ...base, claims: { ...base.claims, ttl: 9 * 86_400 } },
            { clock: clock.now, maxTtlSeconds: 7200 },
        );
        expect((await hi.resolver.resolve({ uri: hi.uri, idx: 0 })).list.cacheUntil.getTime() - clock.now().getTime()).toBe(
            7_200_000,
        );
        const defaultTtlSeconds = randomInt(100, 1000);
        const none = await setup({ ...base, claims: { ...base.claims, ttl: undefined } }, { clock: clock.now, defaultTtlSeconds });
        const lookup = await none.resolver.resolve({ uri: none.uri, idx: 0 });
        expect(lookup.list.ttlSeconds).toBeUndefined();
        expect(lookup.list.cacheUntil.getTime() - clock.now().getTime()).toBe(defaultTtlSeconds * 1000);
    });

    it('bounds the cache (LRU eviction)', async () => {
        const uris = [randomStatusUri(), randomStatusUri(), randomStatusUri()];
        const stub = createStubFetcher();
        for (const uri of uris) stub.set(uri, { body: await buildStatusListJwt({ signer, uri }) });
        const resolver = new StatusListResolver({ trustStore: signer.trustStore, fetcher: stub.fetcher, maxCacheEntries: 2 });
        for (const uri of uris) await resolver.resolve({ uri, idx: 0 });
        expect(stub.calls).toHaveLength(3);
        expect((await resolver.resolve({ uri: uris[2], idx: 0 })).fromCache).toBe(true);
        expect((await resolver.resolve({ uri: uris[0], idx: 0 })).fromCache).toBe(false); // evicted
    });

    it('coalesces concurrent fetches of the same uri', async () => {
        const { uri, stub, resolver } = await setup();
        const results = await Promise.all(Array.from({ length: 5 }, (_, i) => resolver.resolve({ uri, idx: i % 4 })));
        expect(results).toHaveLength(5);
        expect(stub.calls).toHaveLength(1);
    });

    it('does not cache failures', async () => {
        const uri = randomStatusUri();
        const stub = createStubFetcher({ [uri]: { status: 500, body: '' } });
        const resolver = new StatusListResolver({ trustStore: signer.trustStore, fetcher: stub.fetcher });
        await expectReason(resolver.resolve({ uri, idx: 0 }), 'fetch_failed');
        stub.set(uri, { body: await buildStatusListJwt({ signer, uri }) });
        await expect(resolver.resolve({ uri, idx: 0 })).resolves.toBeDefined();
    });

    it('prefetch replaces the cached copy; clearCache drops it', async () => {
        const { uri, stub, resolver } = await setup({ statuses: [0, 0, 0, 0] });
        expect((await resolver.resolve({ uri, idx: 2 })).status).toBe('valid');
        stub.set(uri, { body: await buildStatusListJwt({ signer, uri, statuses: [0, 0, 1, 0] }) });
        expect((await resolver.resolve({ uri, idx: 2 })).status).toBe('valid'); // still cached
        await resolver.prefetch(uri);
        expect((await resolver.resolve({ uri, idx: 2 })).status).toBe('invalid');
        resolver.clearCache();
        expect((await resolver.resolve({ uri, idx: 2 })).fromCache).toBe(false);
    });
});
