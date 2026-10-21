import { randomInt, randomUUID } from 'node:crypto';

import { Encoder as CborEncoder } from 'cbor-x';
import { beforeAll, describe, expect, it } from 'vitest';

import { StatusListError } from '../../src/errors.js';
import { StatusListResolver, type StatusListResolverOptions } from '../../src/status/StatusListResolver.js';
import { cborToPlain, decodeStatusListCwt } from '../../src/status/status-list-cwt.js';

import {
    buildStatusListCwt,
    buildStatusListJwt,
    createClock,
    createStatusListSigner,
    createStubFetcher,
    randomStatuses,
    randomStatusUri,
    x5cToDer,
    type BuildStatusListCwtOptions,
    type StatusListSigner,
} from './helpers.js';

const cbor = new CborEncoder({ mapsAsObjects: false, useRecords: false, tagUint8Array: false });

let signer: StatusListSigner;
let otherSigner: StatusListSigner;

beforeAll(async () => {
    signer = await createStatusListSigner();
    otherSigner = await createStatusListSigner();
});

async function expectReason(p: Promise<unknown>, reason: string): Promise<void> {
    await expect(p).rejects.toSatisfy((err: unknown) => err instanceof StatusListError && err.reason === reason);
}

/** A resolver serving one CWT token at a fresh URI. */
async function setup(
    tokenOpts: Partial<BuildStatusListCwtOptions> = {},
    resolverOpts: Partial<StatusListResolverOptions> = {},
) {
    const uri = tokenOpts.uri ?? randomStatusUri();
    const statuses = tokenOpts.statuses ?? randomStatuses(2, 4 * randomInt(1, 16));
    const token = await buildStatusListCwt({ signer, uri, bits: 2, statuses, ...tokenOpts });
    const stub = createStubFetcher({ [uri]: { body: token } });
    const resolver = new StatusListResolver({ trustStore: signer.trustStore, fetcher: stub.fetcher, ...resolverOpts });
    return { uri, statuses, token, stub, resolver };
}

const CWT = { format: 'cwt' } as const;

describe('StatusListResolver (CWT) — happy path', () => {
    it('resolves every index of a verified CWT list', async () => {
        const { uri, statuses, resolver } = await setup();
        for (let idx = 0; idx < statuses.length; idx++) {
            const lookup = await resolver.resolve({ uri, idx }, CWT);
            expect(lookup.value).toBe(statuses[idx]);
            expect(lookup.status).toBe(['valid', 'invalid', 'suspended', 'unknown'][statuses[idx]]);
            expect(lookup.list.format).toBe('cwt');
        }
    });

    it('sends Accept: application/statuslist+cwt with a GET', async () => {
        const { uri, stub, resolver } = await setup();
        await resolver.resolve({ uri, idx: 0 }, CWT);
        expect(stub.calls).toHaveLength(1);
        expect(stub.calls[0].init?.method).toBe('GET');
        expect(new Headers(stub.calls[0].init?.headers).get('accept')).toBe('application/statuslist+cwt');
    });

    it.each([1, 4, 8] as const)('decodes a %i-bit list', async (bits) => {
        const statuses = randomStatuses(bits, (8 / bits) * randomInt(1, 8));
        const { uri, resolver } = await setup({ bits, statuses });
        const idx = randomInt(0, statuses.length);
        await expect(resolver.resolve({ uri, idx }, CWT)).resolves.toMatchObject({ value: statuses[idx] });
    });

    it.each(['cose', 'cwt'] as const)('accepts the #6.%s-tagged form', async (tag) => {
        const { uri, resolver } = await setup({ tag });
        await expect(resolver.resolve({ uri, idx: 0 }, CWT)).resolves.toBeDefined();
    });

    it('accepts x5chain in the protected header', async () => {
        const { uri, resolver } = await setup({ x5chainIn: 'protected' });
        await expect(resolver.resolve({ uri, idx: 0 }, CWT)).resolves.toBeDefined();
    });

    it('validates a signer under an intermediate carried in x5chain', async () => {
        const chained = await createStatusListSigner({ intermediate: true });
        const uri = randomStatusUri();
        const token = await buildStatusListCwt({ signer: chained, uri, bits: 1, statuses: [0, 1, 0, 0, 0, 0, 0, 0] });
        const resolver = new StatusListResolver({
            trustStore: chained.trustStore,
            fetcher: createStubFetcher({ [uri]: { body: token } }).fetcher,
        });
        await expect(resolver.resolve({ uri, idx: 1 }, CWT)).resolves.toMatchObject({ status: 'invalid', value: 1 });
        expect((await resolver.getStatusList(uri, CWT)).trust.chain).toHaveLength(3);
    });

    it('caches JWT and CWT lists at the same uri separately', async () => {
        const uri = randomStatusUri();
        const jwtStatuses = [0, 0, 0, 0];
        const cwtStatuses = [1, 1, 1, 1];
        const jwt = await buildStatusListJwt({ signer, uri, statuses: jwtStatuses });
        const cwt = await buildStatusListCwt({ signer, uri, statuses: cwtStatuses });
        const fetcher = async (url: string, init?: RequestInit) => {
            const accept = new Headers(init?.headers).get('accept');
            return url === uri
                ? new Response(accept === 'application/statuslist+cwt' ? new Uint8Array(cwt) : jwt)
                : new Response('not found', { status: 404 });
        };
        const resolver = new StatusListResolver({ trustStore: signer.trustStore, fetcher });
        const idx = randomInt(0, 4);
        expect((await resolver.resolve({ uri, idx })).status).toBe('valid');
        expect((await resolver.resolve({ uri, idx }, CWT)).status).toBe('invalid');
        expect((await resolver.resolve({ uri, idx })).fromCache).toBe(true);
        expect((await resolver.resolve({ uri, idx }, CWT)).fromCache).toBe(true);
    });

    it('rejects an unknown format', async () => {
        const { uri, resolver } = await setup();
        await expectReason(resolver.resolve({ uri, idx: 0 }, { format: 'xml' as never }), 'configuration');
    });
});

describe('StatusListResolver (CWT) — token validation failures', () => {
    it('wrong typ', async () => {
        const { uri, resolver } = await setup({ protectedHeader: new Map([[16, 'application/statuslist+jwt']]) });
        await expectReason(resolver.resolve({ uri, idx: 0 }, CWT), 'invalid_token');
    });

    it('typ only in the unprotected header', async () => {
        const { uri, resolver } = await setup({
            protectedHeader: new Map([[16, undefined]]),
            unprotectedHeader: new Map([[16, 'application/statuslist+cwt']]),
        });
        await expect(resolver.resolve({ uri, idx: 0 }, CWT)).rejects.toThrow(/protected header/);
    });

    it('typ as a CoAP content-format number is refused', async () => {
        const { uri, resolver } = await setup({ protectedHeader: new Map([[16, randomInt(1, 65535)]]) });
        await expectReason(resolver.resolve({ uri, idx: 0 }, CWT), 'invalid_token');
    });

    it('unsupported and disallowed alg', async () => {
        const unknown = await setup({ protectedHeader: new Map([[1, -8]]) });
        await expectReason(unknown.resolver.resolve({ uri: unknown.uri, idx: 0 }, CWT), 'invalid_token');
        const disallowed = await setup({}, { allowedAlgorithms: ['ES384'] });
        await expectReason(disallowed.resolver.resolve({ uri: disallowed.uri, idx: 0 }, CWT), 'invalid_token');
    });

    it('bad signature (payload changed after signing)', async () => {
        const { uri, resolver } = await setup({ tamper: true });
        await expectReason(resolver.resolve({ uri, idx: 0 }, CWT), 'signature_invalid');
    });

    it('signature by a key other than x5chain[0]', async () => {
        const uri = randomStatusUri();
        const token = await buildStatusListCwt({ signer: otherSigner, uri, x5chain: x5cToDer(signer.x5c) });
        const resolver = new StatusListResolver({
            trustStore: signer.trustStore,
            fetcher: createStubFetcher({ [uri]: { body: token } }).fetcher,
        });
        await expectReason(resolver.resolve({ uri, idx: 0 }, CWT), 'signature_invalid');
    });

    it('signer that does not chain to the status-list anchors', async () => {
        const uri = randomStatusUri();
        const token = await buildStatusListCwt({ signer: otherSigner, uri });
        const resolver = new StatusListResolver({
            trustStore: signer.trustStore,
            fetcher: createStubFetcher({ [uri]: { body: token } }).fetcher,
        });
        await expectReason(resolver.resolve({ uri, idx: 0 }, CWT), 'untrusted_signer');
    });

    it('trust anchor included in x5chain is refused', async () => {
        const rootDer = new Uint8Array(signer.root.certificate.rawData);
        const { uri, resolver } = await setup({ x5chain: [...x5cToDer(signer.x5c), rootDer] });
        await expectReason(resolver.resolve({ uri, idx: 0 }, CWT), 'untrusted_signer');
    });

    it('anchor never taken from the token: a self-supplied root does not help', async () => {
        // otherSigner's own root rides along in x5chain; the resolver only trusts signer's root.
        const uri = randomStatusUri();
        const token = await buildStatusListCwt({
            signer: otherSigner,
            uri,
            x5chain: [...x5cToDer(otherSigner.x5c), new Uint8Array(otherSigner.root.certificate.rawData)],
        });
        const resolver = new StatusListResolver({
            trustStore: signer.trustStore,
            fetcher: createStubFetcher({ [uri]: { body: token } }).fetcher,
        });
        await expectReason(resolver.resolve({ uri, idx: 0 }, CWT), 'untrusted_signer');
    });

    it('missing x5chain, or x5chain in both headers', async () => {
        const none = await setup({ x5chainIn: 'none' });
        await expectReason(none.resolver.resolve({ uri: none.uri, idx: 0 }, CWT), 'invalid_token');
        const both = await setup({ x5chainIn: 'both' });
        await expectReason(both.resolver.resolve({ uri: both.uri, idx: 0 }, CWT), 'invalid_token');
    });

    it('sub does not match the referenced uri', async () => {
        const { uri, resolver } = await setup({ claims: { sub: randomStatusUri() } });
        await expectReason(resolver.resolve({ uri, idx: 0 }, CWT), 'subject_mismatch');
    });

    it('sub missing', async () => {
        const { uri, resolver } = await setup({ claims: { sub: undefined } });
        await expectReason(resolver.resolve({ uri, idx: 0 }, CWT), 'invalid_token');
    });

    it('expired token (exp passed beyond skew)', async () => {
        const now = Math.floor(Date.now() / 1000);
        const { uri, resolver } = await setup({ claims: { exp: now - randomInt(120, 3600) } });
        await expectReason(resolver.resolve({ uri, idx: 0 }, CWT), 'expired');
    });

    it('iat missing or in the future', async () => {
        const missing = await setup({ claims: { iat: undefined } });
        await expectReason(missing.resolver.resolve({ uri: missing.uri, idx: 0 }, CWT), 'invalid_token');
        const now = Math.floor(Date.now() / 1000);
        const future = await setup({ claims: { iat: now + randomInt(120, 3600) } });
        await expectReason(future.resolver.resolve({ uri: future.uri, idx: 0 }, CWT), 'not_fresh');
    });

    it('nbf in the future', async () => {
        const now = Math.floor(Date.now() / 1000);
        const { uri, resolver } = await setup({ claims: { nbf: now + randomInt(120, 3600) } });
        await expectReason(resolver.resolve({ uri, idx: 0 }, CWT), 'not_fresh');
    });

    it('non-positive ttl', async () => {
        const { uri, resolver } = await setup({ claims: { ttl: -randomInt(0, 100) } });
        await expectReason(resolver.resolve({ uri, idx: 0 }, CWT), 'invalid_token');
    });

    it('status_list missing, with bad bits, or with a base64url text lst', async () => {
        const missing = await setup({ claims: { status_list: undefined } });
        await expectReason(missing.resolver.resolve({ uri: missing.uri, idx: 0 }, CWT), 'malformed_status_list');
        const badBits = await setup({
            claims: { status_list: new Map<string, unknown>([['bits', 3], ['lst', new Uint8Array([1, 2, 3])]]) },
        });
        await expectReason(badBits.resolver.resolve({ uri: badBits.uri, idx: 0 }, CWT), 'malformed_status_list');
        const textLst = await setup({
            claims: { status_list: new Map<string, unknown>([['bits', 1], ['lst', Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('base64url')]]) },
        });
        await expectReason(textLst.resolver.resolve({ uri: textLst.uri, idx: 0 }, CWT), 'malformed_status_list');
    });

    it('status_list lst that is not a ZLIB stream', async () => {
        const { uri, resolver } = await setup({
            claims: {
                status_list: new Map<string, unknown>([
                    ['bits', 1],
                    ['lst', crypto.getRandomValues(new Uint8Array(randomInt(8, 64)))],
                ]),
            },
        });
        await expectReason(resolver.resolve({ uri, idx: 0 }, CWT), 'malformed_status_list');
    });

    it('decompressed list above maxListBytes', async () => {
        const statuses = new Array<number>(8 * randomInt(1024, 4096)).fill(0);
        const { uri, resolver } = await setup({ bits: 1, statuses }, { maxListBytes: 512 });
        await expectReason(resolver.resolve({ uri, idx: 0 }, CWT), 'list_too_large');
    });

    it('index out of range of an authentic list', async () => {
        const { uri, statuses, resolver } = await setup();
        await expectReason(
            resolver.resolve({ uri, idx: statuses.length + randomInt(0, 1000) }, CWT),
            'index_out_of_range',
        );
    });

    it('non-CBOR body, a JWT served to a CWT request, and a non-COSE CBOR body', async () => {
        const uri = randomStatusUri();
        const stub = createStubFetcher({ [uri]: { body: new Uint8Array([0xff, 0xff, 0xff]) } });
        const resolver = new StatusListResolver({ trustStore: signer.trustStore, fetcher: stub.fetcher });
        await expectReason(resolver.resolve({ uri, idx: 0 }, CWT), 'invalid_token');
        stub.set(uri, { body: await buildStatusListJwt({ signer, uri }) });
        await expectReason(resolver.resolve({ uri, idx: 0 }, CWT), 'invalid_token');
        stub.set(uri, { body: new Uint8Array(cbor.encode(new Map([[randomUUID(), randomInt(0, 100)]]))) });
        await expectReason(resolver.resolve({ uri, idx: 0 }, CWT), 'invalid_token');
    });

    it('HTTP error and transport error are fetch_failed', async () => {
        const uri = randomStatusUri();
        const stub = createStubFetcher({ [uri]: { status: 500 + randomInt(0, 4), body: 'down' } });
        const resolver = new StatusListResolver({ trustStore: signer.trustStore, fetcher: stub.fetcher });
        await expectReason(resolver.resolve({ uri, idx: 0 }, CWT), 'fetch_failed');
        stub.set(uri, new Error('ECONNRESET'));
        await expectReason(resolver.resolve({ uri, idx: 0 }, CWT), 'fetch_failed');
    });

    it('uses the HTTPS-only guarded fetcher by default', async () => {
        const resolver = new StatusListResolver({ trustStore: signer.trustStore });
        const uri = `http://status.example.eu/${randomInt(1, 1e6)}`;
        await expect(resolver.resolve({ uri, idx: 0 }, CWT)).rejects.toSatisfy(
            (err: unknown) =>
                err instanceof StatusListError &&
                err.reason === 'fetch_failed' &&
                (err.cause as { reason?: string }).reason === 'insecure_scheme',
        );
    });
});

describe('StatusListResolver (CWT) — caching', () => {
    it('serves from cache within ttl and refetches after it', async () => {
        const clock = createClock();
        const ttl = randomInt(120, 900);
        const nowSeconds = Math.floor(clock.now().getTime() / 1000);
        const { uri, stub, resolver } = await setup(
            { claims: { ttl, exp: nowSeconds + 10 * ttl }, nowSeconds },
            { clock: clock.now },
        );
        expect((await resolver.resolve({ uri, idx: 0 }, CWT)).fromCache).toBe(false);
        clock.advance(ttl - 1);
        expect((await resolver.resolve({ uri, idx: 0 }, CWT)).fromCache).toBe(true);
        clock.advance(2);
        expect((await resolver.resolve({ uri, idx: 0 }, CWT)).fromCache).toBe(false);
        expect(stub.calls).toHaveLength(2);
    });

    it('never caches past exp, even with a longer ttl', async () => {
        const clock = createClock();
        const nowSeconds = Math.floor(clock.now().getTime() / 1000);
        const expIn = randomInt(120, 600);
        const { uri, resolver } = await setup(
            { claims: { ttl: expIn * 10, exp: nowSeconds + expIn }, nowSeconds },
            { clock: clock.now },
        );
        const list = await resolver.getStatusList(uri, CWT);
        expect(list.cacheUntil.getTime()).toBe((nowSeconds + expIn) * 1000);
        expect(list.ttlSeconds).toBe(expIn * 10);
    });

    it('coalesces concurrent fetches of the same uri', async () => {
        const { uri, stub, resolver } = await setup();
        const n = randomInt(2, 8);
        await Promise.all(Array.from({ length: n }, () => resolver.resolve({ uri, idx: 0 }, CWT)));
        expect(stub.calls).toHaveLength(1);
    });

    it('prefetch replaces the cached CWT copy', async () => {
        const { uri, stub, resolver } = await setup();
        await resolver.resolve({ uri, idx: 0 }, CWT);
        await resolver.prefetch(uri, CWT);
        expect(stub.calls).toHaveLength(2);
        expect((await resolver.resolve({ uri, idx: 0 }, CWT)).fromCache).toBe(true);
    });
});

describe('decodeStatusListCwt / cborToPlain', () => {
    it('maps CWT claim labels to their JWT names', async () => {
        const uri = randomStatusUri();
        const ttl = randomInt(60, 6000);
        const decoded = decodeStatusListCwt(await buildStatusListCwt({ signer, uri, claims: { ttl } }), uri);
        expect(decoded.claims['sub']).toBe(uri);
        expect(decoded.claims['ttl']).toBe(ttl);
        expect(decoded.claims['status_list']).toBeInstanceOf(Map);
        expect(decoded.alg).toBe('ES256');
    });

    it('converts text-keyed maps and leaves others for the caller to reject', () => {
        const idx = randomInt(0, 1e6);
        const uri = randomStatusUri();
        const plain = cborToPlain(new Map([['status_list', new Map<string, unknown>([['idx', idx], ['uri', uri]])]]));
        expect(plain).toEqual({ status_list: { idx, uri } });
        const intKeyed = new Map([[randomInt(0, 100), uri]]);
        expect(cborToPlain(intKeyed)).toBe(intKeyed);
    });
});
