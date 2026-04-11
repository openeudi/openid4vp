/**
 * Test fixtures for SD-JWT VC parser tests.
 *
 * These generate minimal SD-JWT strings with base64url-encoded header/payload
 * sections. Signatures are NOT cryptographically valid — they are only used to
 * exercise structural parsing, claim extraction, expiry checking, and trust
 * validation. Cryptographic signature verification is out of scope for unit
 * tests (no real EUDI Wallet credentials available).
 */

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function base64urlEncode(input: string): string {
    // Use Buffer in Node.js environment
    return Buffer.from(input, 'utf-8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function buildJwt(header: Record<string, unknown>, payload: Record<string, unknown>): string {
    const h = base64urlEncode(JSON.stringify(header));
    const p = base64urlEncode(JSON.stringify(payload));
    const fakeSig = base64urlEncode('fake-signature');
    return `${h}.${p}.${fakeSig}`;
}

// ---------------------------------------------------------------------------
// Fake X.509 certificate (DER bytes as base64 for x5c)
// ---------------------------------------------------------------------------

const FAKE_CERT_BYTES_STRING = 'fake-x509-certificate-der-bytes-for-testing';

/** The raw base64 representation placed in the JWT header x5c array. */
export const FAKE_CERT_BASE64 = Buffer.from(FAKE_CERT_BYTES_STRING).toString('base64');

/** The corresponding Uint8Array that the parser will extract. */
export const FAKE_CERT_UINT8 = new Uint8Array(Buffer.from(FAKE_CERT_BYTES_STRING));

// ---------------------------------------------------------------------------
// Shared header with x5c
// ---------------------------------------------------------------------------

const STANDARD_HEADER = {
    alg: 'ES256',
    typ: 'vc+sd-jwt',
    x5c: [FAKE_CERT_BASE64],
};

// ---------------------------------------------------------------------------
// 1. Valid SD-JWT with age_over_18 and resident_country claims
//    Format: <issuerJwt>~<disclosure1>~<disclosure2>~<kbJwt>
// ---------------------------------------------------------------------------

const VALID_NONCE = 'test-nonce-abc123';

const validPayload = {
    iss: 'https://issuer.de/eudi',
    exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
    iat: Math.floor(Date.now() / 1000),
    vct: 'urn:eu.europa.ec.eudi:pid:1',
    age_over_18: true,
    resident_country: 'DE',
};

const validIssuerJwt = buildJwt(STANDARD_HEADER, validPayload);

const kbHeader = { alg: 'ES256', typ: 'kb+jwt' };
const kbPayload = {
    iat: Math.floor(Date.now() / 1000),
    aud: 'https://verifier.example.com',
    nonce: VALID_NONCE,
    sd_hash: 'placeholder-hash',
};
const validKbJwt = buildJwt(kbHeader, kbPayload);

// Fake disclosure strings (base64url-encoded JSON arrays: [salt, key, value])
const disclosure1 = base64urlEncode(JSON.stringify(['salt1', 'age_over_18', true]));
const disclosure2 = base64urlEncode(JSON.stringify(['salt2', 'resident_country', 'DE']));

/** A structurally valid SD-JWT with two disclosures and a key binding JWT. */
export const VALID_SD_JWT = `${validIssuerJwt}~${disclosure1}~${disclosure2}~${validKbJwt}`;

/** The nonce embedded in the valid SD-JWT's key binding JWT. */
export const VALID_SD_JWT_NONCE = VALID_NONCE;

// ---------------------------------------------------------------------------
// 2. Expired SD-JWT (exp in the past)
// ---------------------------------------------------------------------------

const expiredPayload = {
    iss: 'https://issuer.de/eudi',
    exp: Math.floor(Date.now() / 1000) - 7200, // 2 hours ago
    iat: Math.floor(Date.now() / 1000) - 10800,
    vct: 'urn:eu.europa.ec.eudi:pid:1',
    age_over_18: true,
    resident_country: 'DE',
};

const expiredIssuerJwt = buildJwt(STANDARD_HEADER, expiredPayload);

/** An SD-JWT whose exp claim is in the past. */
export const EXPIRED_SD_JWT = `${expiredIssuerJwt}~${disclosure1}~${disclosure2}~`;

// ---------------------------------------------------------------------------
// 3. SD-JWT with untrusted certificate (different x5c)
// ---------------------------------------------------------------------------

const UNTRUSTED_CERT_BYTES_STRING = 'untrusted-certificate-totally-different';

const untrustedHeader = {
    alg: 'ES256',
    typ: 'vc+sd-jwt',
    x5c: [Buffer.from(UNTRUSTED_CERT_BYTES_STRING).toString('base64')],
};

const untrustedIssuerJwt = buildJwt(untrustedHeader, validPayload);

/** An SD-JWT whose issuer certificate is NOT in the trusted set. */
export const UNTRUSTED_SD_JWT = `${untrustedIssuerJwt}~${disclosure1}~`;

// ---------------------------------------------------------------------------
// 4. Malformed strings
// ---------------------------------------------------------------------------

/** A string that looks like a JWT but has no disclosures (no ~). */
export const PLAIN_JWT_NO_TILDE = buildJwt(STANDARD_HEADER, validPayload);

/** A completely garbage string with tildes but invalid base64url segments. */
export const MALFORMED_SD_JWT = '!!!not-a-jwt!!!~garbage~more-garbage~';

// ---------------------------------------------------------------------------
// 5. SD-JWT with mismatched nonce
// ---------------------------------------------------------------------------

const wrongNonceKbPayload = {
    iat: Math.floor(Date.now() / 1000),
    aud: 'https://verifier.example.com',
    nonce: 'wrong-nonce-does-not-match',
    sd_hash: 'placeholder-hash',
};
const wrongNonceKbJwt = buildJwt(kbHeader, wrongNonceKbPayload);

/** An SD-JWT whose key binding JWT nonce does not match the expected value. */
export const WRONG_NONCE_SD_JWT = `${validIssuerJwt}~${disclosure1}~${disclosure2}~${wrongNonceKbJwt}`;
