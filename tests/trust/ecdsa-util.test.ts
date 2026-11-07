import { describe, expect, it } from 'vitest';
import { AsnConvert } from '@peculiar/asn1-schema';
import { CertificateList } from '@peculiar/asn1-x509';
import { ecdsaDerToIeee } from '../../src/trust/ecdsa-util.js';
import { ecdsaIeeeToDer } from './helpers/synthetic-ca.js';
import { DTRUST_PID_SIGNER_TEST_CRL_DER_BASE64 } from '../fixtures/dtrust-pid-signer-test-ca.js';

const CURVES = [
    { namedCurve: 'P-256', hash: 'SHA-256', coordBytes: 32 },
    { namedCurve: 'P-384', hash: 'SHA-384', coordBytes: 48 },
    { namedCurve: 'P-521', hash: 'SHA-512', coordBytes: 66 },
] as const;

async function signIeee(namedCurve: string, hash: string): Promise<Uint8Array> {
    const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve }, false, ['sign']);
    const data = crypto.getRandomValues(new Uint8Array(64));
    return new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash }, keys.privateKey, data));
}

describe('ecdsaDerToIeee', () => {
    for (const { namedCurve, hash, coordBytes } of CURVES) {
        it(`round-trips ${namedCurve} signatures`, async () => {
            for (let i = 0; i < 8; i++) {
                const ieee = await signIeee(namedCurve, hash);
                expect(ecdsaDerToIeee(ecdsaIeeeToDer(ieee), coordBytes)).toEqual(ieee);
            }
        });
    }

    it('parses the long-form SEQUENCE length of the D-Trust P-521 CRL signature (#73)', () => {
        const crl = AsnConvert.parse(
            Buffer.from(DTRUST_PID_SIGNER_TEST_CRL_DER_BASE64, 'base64'),
            CertificateList
        );
        const der = new Uint8Array(crl.signature);
        expect(Array.from(der.subarray(0, 5))).toEqual([0x30, 0x81, 0x88, 0x02, 0x42]);
        const ieee = ecdsaDerToIeee(der, 66);
        expect(ieee).toHaveLength(132);
        // r is the 66-byte INTEGER right after `02 42`.
        expect(ieee.subarray(0, 66)).toEqual(der.subarray(5, 71));
    });

    // 30 06 02 01 01 02 01 02 — SEQUENCE { INTEGER 1, INTEGER 2 }
    const valid = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];

    it('accepts a minimal well-formed signature', () => {
        const ieee = ecdsaDerToIeee(new Uint8Array(valid), 32);
        expect(ieee[31]).toBe(1);
        expect(ieee[63]).toBe(2);
    });

    it.each([
        ['wrong outer tag', [0x31, ...valid.slice(1)]],
        ['SEQUENCE length past the end', [0x30, 0x07, ...valid.slice(2)]],
        ['SEQUENCE length short of the content', [0x30, 0x05, ...valid.slice(2)]],
        ['trailing bytes after the SEQUENCE', [...valid, 0x00]],
        ['trailing bytes inside the SEQUENCE', [0x30, 0x07, ...valid.slice(2), 0x00]],
        ['negative INTEGER', [0x30, 0x06, 0x02, 0x01, 0x81, 0x02, 0x01, 0x02]],
        ['indefinite length', [0x30, 0x80, ...valid.slice(2), 0x00, 0x00]],
        ['non-minimal long-form length', [0x30, 0x81, 0x06, ...valid.slice(2)]],
        ['length of length too large', [0x30, 0x85, 0x00, 0x00, 0x00, 0x00, 0x06, ...valid.slice(2)]],
        ['INTEGER length past the SEQUENCE', [0x30, 0x06, 0x02, 0x05, 0x01, 0x02, 0x01, 0x02]],
        ['missing s', [0x30, 0x03, 0x02, 0x01, 0x01]],
        ['empty INTEGER', [0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x02]],
        ['truncated input', [0x30]],
    ])('rejects %s', (_label, bytes) => {
        expect(() => ecdsaDerToIeee(new Uint8Array(bytes), 32)).toThrow(/invalid DER signature/);
    });

    it('rejects an integer wider than the curve', () => {
        const r = [0x01, ...new Array(32).fill(0xff)]; // 33 significant bytes
        const der = [0x30, 2 + r.length + 3, 0x02, r.length, ...r, 0x02, 0x01, 0x02];
        expect(() => ecdsaDerToIeee(new Uint8Array(der), 32)).toThrow(/invalid DER signature/);
    });

    it('drops the sign-padding zero of a full-width integer', () => {
        const r = [0x00, 0x80, ...new Array(31).fill(0x11)]; // 33 bytes, leading 0x00
        const der = [0x30, 2 + r.length + 3, 0x02, r.length, ...r, 0x02, 0x01, 0x02];
        const ieee = ecdsaDerToIeee(new Uint8Array(der), 32);
        expect(Array.from(ieee.subarray(0, 32))).toEqual(r.slice(1));
    });
});
