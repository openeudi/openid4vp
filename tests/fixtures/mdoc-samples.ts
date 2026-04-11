/**
 * Test fixtures for mDOC parser tests.
 *
 * These generate minimal CBOR-encoded DeviceResponse structures matching
 * the ISO 18013-5 format. Cryptographic signatures are NOT valid -- they
 * are only used to exercise structural parsing, claim extraction, expiry
 * checking, and trust validation. Full COSE signature verification is out
 * of scope for unit tests (no real EUDI Wallet mDOC credentials available).
 */

import { encode } from 'cbor-x';

// ---------------------------------------------------------------------------
// Fake issuer certificate (DER-like bytes for trust matching)
// ---------------------------------------------------------------------------

const FAKE_CERT_STRING = 'fake-mdoc-issuer-certificate-der-bytes';

/** Raw certificate bytes that will be embedded in the COSE_Sign1 unprotected header. */
export const FAKE_MDOC_CERT = new Uint8Array(Buffer.from(FAKE_CERT_STRING));

// ---------------------------------------------------------------------------
// Helper: build a COSE_Sign1 issuerAuth structure
// ---------------------------------------------------------------------------

/**
 * Builds a minimal COSE_Sign1 array: [protected, unprotected, payload, signature].
 *
 * - protected: CBOR-encoded empty map (minimal valid header)
 * - unprotected: Map with x5chain (label 33) containing the issuer certificate
 * - payload: CBOR-encoded MobileSecurityObject with validityInfo
 * - signature: fake bytes
 */
function buildIssuerAuth(certBytes: Uint8Array, validityInfo?: { validFrom: string; validUntil: string }): unknown[] {
    const protectedHeader = encode({});
    const unprotectedHeader = new Map<number, Uint8Array>();
    unprotectedHeader.set(33, certBytes);

    const mso: Record<string, unknown> = { version: '1.0', digestAlgorithm: 'SHA-256' };
    if (validityInfo) {
        mso['validityInfo'] = {
            validFrom: validityInfo.validFrom,
            validUntil: validityInfo.validUntil,
        };
    }
    const payload = encode(mso);

    const fakeSignature = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);

    return [protectedHeader, unprotectedHeader, payload, fakeSignature];
}

// ---------------------------------------------------------------------------
// Helper: build IssuerSignedItem elements
// ---------------------------------------------------------------------------

function buildIssuerSignedItem(
    digestID: number,
    elementIdentifier: string,
    elementValue: unknown
): Record<string, unknown> {
    return {
        digestID,
        random: new Uint8Array([0x01, 0x02, 0x03, 0x04]),
        elementIdentifier,
        elementValue,
    };
}

// ---------------------------------------------------------------------------
// 1. Valid mDOC DeviceResponse with age_over_18 and resident_country
// ---------------------------------------------------------------------------

const validNameSpaceItems = [
    buildIssuerSignedItem(0, 'age_over_18', true),
    buildIssuerSignedItem(1, 'resident_country', 'DE'),
];

const validIssuerAuth = buildIssuerAuth(FAKE_MDOC_CERT, {
    validFrom: new Date(Date.now() - 3600_000).toISOString(),
    validUntil: new Date(Date.now() + 3600_000).toISOString(),
});

const validDeviceResponse = {
    version: '1.0',
    documents: [
        {
            docType: 'eu.europa.ec.eudi.pid.1',
            issuerSigned: {
                nameSpaces: {
                    'eu.europa.ec.eudi.pid.1': validNameSpaceItems,
                },
                issuerAuth: validIssuerAuth,
            },
        },
    ],
    status: 0,
};

/** A CBOR-encoded valid mDOC DeviceResponse with age_over_18: true and resident_country: 'DE'. */
export const VALID_MDOC = encode(validDeviceResponse);

// ---------------------------------------------------------------------------
// 2. Expired mDOC (validUntil in the past)
// ---------------------------------------------------------------------------

const expiredIssuerAuth = buildIssuerAuth(FAKE_MDOC_CERT, {
    validFrom: new Date(Date.now() - 7200_000).toISOString(),
    validUntil: new Date(Date.now() - 3600_000).toISOString(),
});

const expiredDeviceResponse = {
    version: '1.0',
    documents: [
        {
            docType: 'eu.europa.ec.eudi.pid.1',
            issuerSigned: {
                nameSpaces: {
                    'eu.europa.ec.eudi.pid.1': validNameSpaceItems,
                },
                issuerAuth: expiredIssuerAuth,
            },
        },
    ],
    status: 0,
};

/** A CBOR-encoded mDOC whose validUntil is in the past. */
export const EXPIRED_MDOC = encode(expiredDeviceResponse);

// ---------------------------------------------------------------------------
// 3. mDOC with untrusted certificate
// ---------------------------------------------------------------------------

const UNTRUSTED_CERT = new Uint8Array(Buffer.from('untrusted-mdoc-certificate-totally-different'));

const untrustedIssuerAuth = buildIssuerAuth(UNTRUSTED_CERT, {
    validFrom: new Date(Date.now() - 3600_000).toISOString(),
    validUntil: new Date(Date.now() + 3600_000).toISOString(),
});

const untrustedDeviceResponse = {
    version: '1.0',
    documents: [
        {
            docType: 'eu.europa.ec.eudi.pid.1',
            issuerSigned: {
                nameSpaces: {
                    'eu.europa.ec.eudi.pid.1': validNameSpaceItems,
                },
                issuerAuth: untrustedIssuerAuth,
            },
        },
    ],
    status: 0,
};

/** A CBOR-encoded mDOC whose issuer certificate is NOT in the trusted set. */
export const UNTRUSTED_MDOC = encode(untrustedDeviceResponse);

// ---------------------------------------------------------------------------
// 4. Malformed CBOR blob (not a valid DeviceResponse)
// ---------------------------------------------------------------------------

/** Random bytes that are not valid CBOR. */
export const MALFORMED_MDOC = new Uint8Array([0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0x00, 0x01]);
