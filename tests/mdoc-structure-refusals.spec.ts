/**
 * mdoc structures a verifier must refuse although every signature verifies:
 * COSE protected headers with an unknown `crit` label or a repeated label
 * (RFC 9052 §3, §3.1), and, per ISO/IEC 18013-5, an IssuerAuth payload that
 * is not MobileSecurityObjectBytes, device-signed elements the MSO's
 * KeyAuthorizations do not cover, and a DeviceSignature that carries its
 * payload instead of detaching it.
 */

import { Encoder as CborEncoder } from 'cbor-x';
import { beforeAll, describe, expect, it } from 'vitest';

import { MdocParser } from '../src/parsers/mdoc.parser.js';
import type { ParseOptions } from '../src/parsers/parser.interface.js';

import { generateTestKeyMaterial, type TestKeyMaterial } from './fixtures/crypto-helpers.js';
import { buildSignedMdoc, type BuildSignedMdocOptions } from './fixtures/mdoc-helpers.js';

const cbor = new CborEncoder({ mapsAsObjects: false, useRecords: false, tagUint8Array: false });
const parser = new MdocParser();
const NS = 'eu.europa.ec.eudi.pid.1';

let issuerKey: TestKeyMaterial;

beforeAll(async () => {
    issuerKey = await generateTestKeyMaterial();
});

async function parse(overrides: Partial<BuildSignedMdocOptions>): Promise<{ valid: boolean; error?: string }> {
    const built = await buildSignedMdoc({
        issuerKey,
        namespaces: { [NS]: { age_over_18: true, family_name: 'Doe' } },
        ...overrides,
    });
    const options: ParseOptions = {
        trustedCertificates: [issuerKey.certDerBytes],
        nonce: 'n',
        mdocSessionTranscript: built.sessionTranscript,
    };
    try {
        const result = await parser.parse(built.mdocBytes, options);
        return { valid: result.valid, error: result.error };
    } catch (err) {
        return { valid: false, error: (err as Error).message };
    }
}

async function expectRefused(overrides: Partial<BuildSignedMdocOptions>, reason: RegExp): Promise<void> {
    const r = await parse(overrides);
    expect(r.valid).toBe(false);
    expect(r.error).toMatch(reason);
}

/** Encoded protected header map from raw CBOR bytes (lets tests repeat a label). */
const bytes = (...b: number[]): Uint8Array => new Uint8Array(b);
// ES256 = -7 = 0x26. Labels: 1 alg, 2 crit, 4 kid.
const ALG_ONLY = bytes(0xa1, 0x01, 0x26);

describe('control', () => {
    it('accepts the unmodified mdoc', async () => {
        expect(await parse({})).toEqual({ valid: true, error: undefined });
    });

    it('accepts an explicit protected header equal to the default', async () => {
        expect((await parse({ issuerProtectedHeader: ALG_ONLY, deviceProtectedHeader: ALG_ONLY })).valid).toBe(true);
    });
});

describe('COSE protected header (RFC 9052 §3, §3.1)', () => {
    const header = (entries: Array<[number, unknown]>): Uint8Array => cbor.encode(new Map(entries));

    it('refuses an IssuerAuth crit naming a label the verifier does not understand', async () => {
        await expectRefused(
            { issuerProtectedHeader: header([[1, -7], [2, [-65537]], [-65537, 'x']]) },
            /crit/
        );
    });

    it('refuses a DeviceSignature crit naming a label the verifier does not understand', async () => {
        await expectRefused(
            { deviceProtectedHeader: header([[1, -7], [2, [-65537]], [-65537, 'x']]) },
            /crit/
        );
    });

    it('refuses a crit that is empty or not an array', async () => {
        await expectRefused({ issuerProtectedHeader: header([[1, -7], [2, []]]) }, /crit/);
        await expectRefused({ issuerProtectedHeader: header([[1, -7], [2, 4]]) }, /crit/);
    });

    it('accepts crit naming alg, which the verifier processes', async () => {
        expect((await parse({ issuerProtectedHeader: header([[1, -7], [2, [1]]]) })).valid).toBe(true);
    });

    it('refuses an IssuerAuth protected header that repeats a label', async () => {
        // {1: -7, 1: -7}
        await expectRefused({ issuerProtectedHeader: bytes(0xa2, 0x01, 0x26, 0x01, 0x26) }, /label/);
    });

    it('refuses a repeated label even when the repeats use different encodings', async () => {
        // {1: -7, 1 (as 0x18 0x01): -7}
        await expectRefused({ issuerProtectedHeader: bytes(0xa2, 0x01, 0x26, 0x18, 0x01, 0x26) }, /label/);
    });

    it('refuses a DeviceSignature protected header that repeats a label', async () => {
        await expectRefused({ deviceProtectedHeader: bytes(0xa2, 0x01, 0x26, 0x01, 0x26) }, /label/);
    });

    it('refuses an indefinite-length protected header map that repeats a label', async () => {
        await expectRefused({ issuerProtectedHeader: bytes(0xbf, 0x01, 0x26, 0x01, 0x26, 0xff) }, /label/);
    });

    it('refuses trailing bytes after the protected header map', async () => {
        await expectRefused({ issuerProtectedHeader: bytes(0xa1, 0x01, 0x26, 0x00) }, /protected header/);
    });
});

describe('IssuerAuth payload (ISO/IEC 18013-5 MobileSecurityObjectBytes)', () => {
    it('refuses a payload that is the bare MSO instead of MobileSecurityObjectBytes', async () => {
        await expectRefused({ bareMso: true }, /MobileSecurityObjectBytes|tag 24|tag-24/);
    });
});

describe('device-signed elements and KeyAuthorizations (ISO/IEC 18013-5)', () => {
    const deviceNs = (ns: string, entries: Record<string, unknown>) =>
        new Map([[ns, new Map(Object.entries(entries))]]);

    it('refuses a device-signed element when the MSO has no KeyAuthorizations', async () => {
        await expectRefused({ deviceNameSpaces: deviceNs(NS, { nickname: 'x' }) }, /KeyAuthorizations/);
    });

    it('refuses a device-signed element in a name space KeyAuthorizations do not list', async () => {
        await expectRefused(
            {
                keyAuthorizations: new Map([['nameSpaces', ['org.example.other']]]),
                deviceNameSpaces: deviceNs(NS, { nickname: 'x' }),
            },
            /KeyAuthorizations/
        );
    });

    it('refuses a device-signed element KeyAuthorizations.dataElements do not list', async () => {
        await expectRefused(
            {
                keyAuthorizations: new Map([['dataElements', new Map([[NS, ['other_element']]])]]),
                deviceNameSpaces: deviceNs(NS, { nickname: 'x' }),
            },
            /KeyAuthorizations/
        );
    });

    it('accepts a device-signed element whose name space is authorized', async () => {
        const r = await parse({
            keyAuthorizations: new Map([['nameSpaces', [NS]]]),
            deviceNameSpaces: deviceNs(NS, { nickname: 'x' }),
        });
        expect(r).toEqual({ valid: true, error: undefined });
    });

    it('accepts a device-signed element listed in dataElements', async () => {
        const r = await parse({
            keyAuthorizations: new Map([['dataElements', new Map([[NS, ['nickname']]])]]),
            deviceNameSpaces: deviceNs(NS, { nickname: 'x' }),
        });
        expect(r).toEqual({ valid: true, error: undefined });
    });

    it('refuses malformed KeyAuthorizations', async () => {
        await expectRefused({ keyAuthorizations: new Map([['nameSpaces', NS]]) }, /KeyAuthorizations/);
        await expectRefused(
            { keyAuthorizations: new Map([['dataElements', new Map([[NS, 'nickname']])]]) },
            /KeyAuthorizations/
        );
    });
});

describe('DeviceSignature payload (ISO/IEC 18013-5 detached DeviceSignature)', () => {
    it('refuses a DeviceSignature that carries its payload instead of detaching it', async () => {
        await expectRefused({ attachDevicePayload: true }, /detached/);
    });
});
