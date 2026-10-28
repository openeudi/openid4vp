/**
 * ISO/IEC 18013-7 Annex C (`org-iso-mdoc`) — byte compatibility with another
 * implementation. The ISO text is paywalled, so these fixed vectors are the
 * cross-check that our wire format is not just self-consistent.
 *
 * Vectors: walt.id `waltid-identity` @ 00917b62 (Apache-2.0),
 * `waltid-libraries/protocols/waltid-18013-7-verifier/src/jvmTest/resources/annex-c/`,
 * copied unchanged into tests/fixtures/annex-c/.
 *
 * - ANNEXC-DETERMINISTIC-001: request, EncryptionInfo, HPKE-encrypted response
 *   and recipient private key, with the expected SHA-256 of the CBOR
 *   SessionTranscript and of the decrypted DeviceResponse.
 * - ANNEXC-REAL-001: a request captured from the multipaz verifier
 *   (https://verifier.multipaz.org) and the wallet's encrypted response, with
 *   the expected transcript hash. Its `recipientPrivateKeyHex` is a generated
 *   placeholder (walt.id's harness says so; it does not match the request's
 *   recipient key), so the response cannot be decrypted by anyone.
 */
import { Encoder as CborEncoder } from 'cbor-x';
import { describe, expect, it } from 'vitest';

import { buildDCAPIHandoverSessionTranscript } from '../src/crypto/session-transcript.js';
import { encodeDeviceRequest, encodeEncryptionInfo, openIsoMdocResponse } from '../src/dc-api/iso-mdoc.js';
import { DcApiResponseError } from '../src/dc-api/errors.js';
import { bytesToBase64Url, bytesToHex, hexToBytes } from '../src/encoding/base64url.js';
import { DecryptionFailedError } from '../src/errors.js';
import deterministic from './fixtures/annex-c/ANNEXC-DETERMINISTIC-001.json';
import real from './fixtures/annex-c/ANNEXC-REAL-001.json';

const cbor = new CborEncoder({ mapsAsObjects: false, useRecords: false });

async function sha256Hex(bytes: Uint8Array): Promise<string> {
    return bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
}

/** Pull nonce and recipient key out of a vector's EncryptionInfo, independently of src/. */
function encryptionInfoParts(encryptionInfoB64: string): { nonce: Uint8Array; x: Uint8Array; y: Uint8Array } {
    const [type, params] = cbor.decode(Buffer.from(encryptionInfoB64, 'base64url')) as [string, Map<string, unknown>];
    expect(type).toBe('dcapi');
    const key = params.get('recipientPublicKey') as Map<number, Uint8Array>;
    return {
        nonce: new Uint8Array(params.get('nonce') as Uint8Array),
        x: new Uint8Array(key.get(-2) as Uint8Array),
        y: new Uint8Array(key.get(-3) as Uint8Array),
    };
}

describe('Annex C cross-check — walt.id ANNEXC-DETERMINISTIC-001', () => {
    it('builds the same CBOR SessionTranscript (HPKE info)', async () => {
        const transcript = await buildDCAPIHandoverSessionTranscript({
            encryptionInfo: deterministic.encryptionInfoB64,
            origin: deterministic.origin,
        });

        expect(await sha256Hex(transcript)).toBe(deterministic.expected.sessionTranscriptCborSha256Hex);
    });

    it('decrypts the HPKE response to the expected DeviceResponse', async () => {
        const opened = await openIsoMdocResponse(
            { response: deterministic.encryptedResponseB64 },
            {
                origin: deterministic.origin,
                encryptionInfo: deterministic.encryptionInfoB64,
                // The vector gives the raw scalar only; x and y come from EncryptionInfo.
                decryptionKey: { kty: 'EC', crv: 'P-256', d: bytesToBase64Url(hexToBytes(deterministic.recipientPrivateKeyHex)) },
            },
        );

        expect(await sha256Hex(opened.deviceResponse)).toBe(deterministic.expected.deviceResponseCborSha256Hex);
        expect(await sha256Hex(opened.sessionTranscript)).toBe(deterministic.expected.sessionTranscriptCborSha256Hex);
        const deviceResponse = cbor.decode(opened.deviceResponse) as Map<string, unknown>;
        expect(deviceResponse.get('version')).toBe('1.0');
        expect(deviceResponse.get('status')).toBe(0);
    });

    it('fails to decrypt for another origin', async () => {
        await expect(
            openIsoMdocResponse(
                { response: deterministic.encryptedResponseB64 },
                {
                    origin: `https://other-${crypto.randomUUID()}.example`,
                    encryptionInfo: deterministic.encryptionInfoB64,
                    decryptionKey: {
                        kty: 'EC',
                        crv: 'P-256',
                        d: bytesToBase64Url(hexToBytes(deterministic.recipientPrivateKeyHex)),
                    },
                },
            ),
        ).rejects.toBeInstanceOf(DecryptionFailedError);
    });

    it('encodes EncryptionInfo byte for byte', () => {
        const { nonce, x, y } = encryptionInfoParts(deterministic.encryptionInfoB64);

        expect(encodeEncryptionInfo(nonce, x, y)).toBe(deterministic.encryptionInfoB64);
    });

    it('encodes the DeviceRequest 1.0 byte for byte', () => {
        expect(
            encodeDeviceRequest({
                docType: deterministic.expected.docType,
                nameSpaces: new Map([['org.iso.18013.5.1', new Map([[deterministic.expected.requestedElement, false]])]]),
            }),
        ).toBe(deterministic.deviceRequestB64);
    });
});

describe('Annex C cross-check — multipaz request captured in walt.id ANNEXC-REAL-001', () => {
    it('builds the same SessionTranscript as walt.id for a real multipaz EncryptionInfo and origin', async () => {
        const transcript = await buildDCAPIHandoverSessionTranscript({
            encryptionInfo: real.encryptionInfoB64,
            origin: real.origin,
        });

        expect(await sha256Hex(transcript)).toBe(real.expected.sessionTranscriptCborSha256Hex);
    });

    it('re-encodes the multipaz EncryptionInfo byte for byte', () => {
        const { nonce, x, y } = encryptionInfoParts(real.encryptionInfoB64);

        expect(encodeEncryptionInfo(nonce, x, y)).toBe(real.encryptionInfoB64);
    });

    it('parses the wallet-produced EncryptedResponse and reaches HPKE (wrong key fails there)', async () => {
        const other = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);

        await expect(
            openIsoMdocResponse(
                { response: real.encryptedResponseB64 },
                { origin: real.origin, encryptionInfo: real.encryptionInfoB64, decryptionKey: other.privateKey },
            ),
        ).rejects.toBeInstanceOf(DecryptionFailedError);
    });

    it('refuses a private JWK that is not the EncryptionInfo recipient key before decrypting', async () => {
        const error = await openIsoMdocResponse(
            { response: real.encryptedResponseB64 },
            {
                origin: real.origin,
                encryptionInfo: real.encryptionInfoB64,
                decryptionKey: { kty: 'EC', crv: 'P-256', d: bytesToBase64Url(hexToBytes(real.recipientPrivateKeyHex)) },
            },
        ).catch((err: unknown) => err);

        expect(error).toBeInstanceOf(DcApiResponseError);
        expect((error as DcApiResponseError).code).toBe('decryption_key_mismatch');
    });
});
