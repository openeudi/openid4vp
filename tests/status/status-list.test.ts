import { randomBytes, randomInt } from 'node:crypto';
import { deflateRawSync, deflateSync } from 'node:zlib';

import * as jose from 'jose';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { StatusListError } from '../../src/errors.js';
import {
    decodeStatusList,
    inflateStatusList,
    readStatusValue,
    toTokenStatusType,
} from '../../src/status/status-list.js';
import { ALL_VECTORS, SECTION_4_1_BIT, SECTION_4_2_BIT } from '../fixtures/status-list-vectors.js';

import { compressToLst, packStatuses, randomStatuses, randomStatusUri } from './helpers.js';

const uri = randomStatusUri();

async function expectReason(p: Promise<unknown> | (() => unknown), reason: string): Promise<void> {
    const run = typeof p === 'function' ? Promise.resolve().then(p) : p;
    await expect(run).rejects.toSatisfy((err: unknown) => err instanceof StatusListError && err.reason === reason);
}

describe('decodeStatusList — draft-ietf-oauth-status-list-21 test vectors', () => {
    for (const vector of ALL_VECTORS) {
        it(`${vector.name}: decodes and reads every listed index`, async () => {
            const list = await decodeStatusList({ bits: vector.bits, lst: vector.lst }, { uri });
            expect(list.bits).toBe(vector.bits);
            expect(list.bytes.length).toBe(vector.byteLength);
            expect(list.size).toBe((vector.byteLength * 8) / vector.bits);
            for (const [idx, value] of Object.entries(vector.statuses)) {
                expect(readStatusValue(list, Number(idx), uri)).toBe(value);
            }
        });

        it(`${vector.name}: unlisted indices are VALID`, async () => {
            const list = await decodeStatusList({ bits: vector.bits, lst: vector.lst }, { uri });
            const listed = new Set(Object.keys(vector.statuses).map(Number));
            for (let n = 0; n < 50; n++) {
                const idx = randomInt(0, list.size);
                if (listed.has(idx)) continue;
                expect(readStatusValue(list, idx, uri)).toBe(0);
            }
        });
    }

    it('§4.1 byte layout: 1-bit list is 0xB9 0xA3, 2-bit list is 0xC9 0x44 0xF9', async () => {
        const one = await decodeStatusList({ bits: 1, lst: SECTION_4_1_BIT.lst }, { uri });
        expect([...one.bytes]).toEqual([0xb9, 0xa3]);
        const two = await decodeStatusList({ bits: 2, lst: SECTION_4_2_BIT.lst }, { uri });
        expect([...two.bytes]).toEqual([0xc9, 0x44, 0xf9]);
    });
});

describe('decodeStatusList — random round trips', () => {
    for (const bits of [1, 2, 4, 8] as const) {
        it(`bits=${bits}: every index reads back the packed value`, async () => {
            const count = randomInt(1, 64) * (8 / bits); // whole bytes, no padding entries
            const values = randomStatuses(bits, count);
            const list = await decodeStatusList({ bits, lst: compressToLst(packStatuses(bits, values)) }, { uri });
            expect(list.size).toBe(count);
            values.forEach((v, i) => expect(readStatusValue(list, i, uri)).toBe(v));
        });
    }
});

describe('readStatusValue', () => {
    it('rejects an index past the end as index_out_of_range (§8.3 step 6)', async () => {
        const bits = ([1, 2, 4, 8] as const)[randomInt(0, 4)];
        const list = await decodeStatusList({ bits, lst: compressToLst(randomBytes(randomInt(1, 32))) }, { uri });
        await expectReason(() => readStatusValue(list, list.size, uri), 'index_out_of_range');
        await expectReason(() => readStatusValue(list, list.size + randomInt(1, 1000), uri), 'index_out_of_range');
        expect(() => readStatusValue(list, list.size - 1, uri)).not.toThrow();
    });

    it('rejects negative, fractional and unsafe indices as invalid_reference', async () => {
        const list = await decodeStatusList({ bits: 1, lst: SECTION_4_1_BIT.lst }, { uri });
        for (const idx of [-1, 1.5, Number.NaN, Number.MAX_SAFE_INTEGER + 2]) {
            await expectReason(() => readStatusValue(list, idx, uri), 'invalid_reference');
        }
    });
});

describe('decodeStatusList — malformed input', () => {
    it.each([0, 3, 16, '1', null])('rejects bits=%s', async (bits) => {
        await expectReason(decodeStatusList({ bits, lst: SECTION_4_1_BIT.lst }, { uri }), 'malformed_status_list');
    });

    it.each([undefined, '', 'not base64url!', 'ab+/', 42])('rejects lst=%s', async (lst) => {
        await expectReason(decodeStatusList({ bits: 1, lst }, { uri }), 'malformed_status_list');
    });

    it.each([null, [], 'x'])('rejects a non-object status_list %s', async (value) => {
        await expectReason(decodeStatusList(value, { uri }), 'malformed_status_list');
    });

    it('rejects bytes that are not a ZLIB stream (raw DEFLATE, random, truncated, trailing junk)', async () => {
        const bytes = randomBytes(64);
        const zlibbed = deflateSync(bytes);
        const cases = [
            deflateRawSync(bytes), // DEFLATE without the ZLIB header
            randomBytes(32),
            zlibbed.subarray(0, zlibbed.length - 3),
            Buffer.concat([zlibbed, randomBytes(4)]),
        ];
        for (const c of cases) {
            await expectReason(decodeStatusList({ bits: 1, lst: jose.base64url.encode(c) }, { uri }), 'malformed_status_list');
        }
    });

    it('rejects an empty list', async () => {
        await expectReason(decodeStatusList({ bits: 1, lst: compressToLst(new Uint8Array(0)) }, { uri }), 'malformed_status_list');
    });

    it('caps decompressed output (DEFLATE bomb) with list_too_large', async () => {
        const maxBytes = randomInt(1024, 4096);
        const bomb = compressToLst(new Uint8Array(maxBytes * 64)); // zeros compress ~1000:1
        await expectReason(decodeStatusList({ bits: 1, lst: bomb }, { uri, maxBytes }), 'list_too_large');
        await expect(
            decodeStatusList({ bits: 1, lst: compressToLst(new Uint8Array(maxBytes)) }, { uri, maxBytes }),
        ).resolves.toMatchObject({ size: maxBytes * 8 });
    });
});

describe('inflateStatusList — node:zlib fallback when DecompressionStream is unavailable', () => {
    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it('inflates via node:zlib and still enforces the size cap', async () => {
        vi.stubGlobal('DecompressionStream', undefined);
        const bytes = randomBytes(randomInt(16, 256));
        await expect(inflateStatusList(deflateSync(bytes), { uri })).resolves.toEqual(new Uint8Array(bytes));
        await expectReason(inflateStatusList(deflateSync(new Uint8Array(8192)), { uri, maxBytes: 1024 }), 'list_too_large');
        await expectReason(inflateStatusList(randomBytes(32), { uri }), 'malformed_status_list');
    });
});

describe('toTokenStatusType', () => {
    it('maps §7.1 values and reports everything else as unknown', () => {
        expect(toTokenStatusType(0)).toBe('valid');
        expect(toTokenStatusType(1)).toBe('invalid');
        expect(toTokenStatusType(2)).toBe('suspended');
        expect(toTokenStatusType(randomInt(3, 256))).toBe('unknown');
    });
});
