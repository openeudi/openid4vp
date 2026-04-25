/**
 * Crypto test helpers for generating real EC key pairs, self-signed X.509
 * certificates, and cryptographically valid SD-JWT tokens.
 */

import { X509CertificateGenerator } from '@peculiar/x509';
import * as jose from 'jose';

// ----------------------------------------------------------------
// Types
// ----------------------------------------------------------------

export interface TestKeyMaterial {
    privateKey: CryptoKey;
    publicKey: CryptoKey;
    /** Base64-encoded DER certificate for JWT x5c header. */
    x5cBase64: string;
    /** Raw DER bytes for trust checking via ParseOptions.trustedCertificates. */
    certDerBytes: Uint8Array;
}

export interface BuildSdJwtOptions {
    issuerKey: TestKeyMaterial;
    holderKey?: TestKeyMaterial;
    /** Claims placed directly in the JWT payload (not selectively disclosed). */
    claims?: Record<string, unknown>;
    /** Claims to selectively disclose: [key, value] pairs hashed into _sd. */
    disclosureClaims?: Array<[string, unknown]>;
    nonce?: string;
    audience?: string;
    /** Seconds until expiry from now. Negative values create expired tokens. */
    expSeconds?: number;
    alg?: string;
    typ?: string;
}

export interface BuildSdJwtResult {
    /** The complete SD-JWT string: issuerJwt~disc1~disc2~...~kbJwt */
    sdJwt: string;
    /** The issuer JWT component (for tampering tests). */
    issuerJwt: string;
    /** Raw disclosure strings (for tampering tests). */
    disclosures: string[];
    /** The key binding JWT component (undefined if no holder key/nonce). */
    kbJwt: string | undefined;
    /** The _sd hashes placed in the issuer JWT payload. */
    sdHashes: string[];
}

// ----------------------------------------------------------------
// Key generation
// ----------------------------------------------------------------

export async function generateTestKeyMaterial(alg: string = 'ES256'): Promise<TestKeyMaterial> {
    const namedCurve = alg === 'ES384' ? 'P-384' : alg === 'ES512' ? 'P-521' : 'P-256';

    const keyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve }, true, ['sign', 'verify']);

    const hashAlg = alg === 'ES384' ? 'SHA-384' : alg === 'ES512' ? 'SHA-512' : 'SHA-256';

    const cert = await X509CertificateGenerator.createSelfSigned({
        serialNumber: crypto.randomUUID().replace(/-/g, ''),
        name: 'CN=Test Issuer,C=DE',
        notBefore: new Date(),
        notAfter: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
        keys: keyPair,
        signingAlgorithm: { name: 'ECDSA', hash: hashAlg },
    });

    const derBytes = new Uint8Array(cert.rawData);
    const x5cBase64 = Buffer.from(derBytes).toString('base64');

    return {
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        x5cBase64,
        certDerBytes: derBytes,
    };
}

// ----------------------------------------------------------------
// SD-JWT assembly
// ----------------------------------------------------------------

export async function buildSignedSdJwt(options: BuildSdJwtOptions): Promise<BuildSdJwtResult> {
    const {
        issuerKey,
        holderKey,
        claims = {},
        disclosureClaims = [],
        nonce,
        audience,
        expSeconds = 3600,
        alg = 'ES256',
        typ = 'vc+sd-jwt',
    } = options;

    // Build disclosures and compute their SHA-256 hashes
    const disclosures: string[] = [];
    const sdHashes: string[] = [];

    for (const [key, value] of disclosureClaims) {
        const salt = crypto.randomUUID();
        const disclosureJson = JSON.stringify([salt, key, value]);
        const disclosureB64 = base64urlEncodeString(disclosureJson);
        disclosures.push(disclosureB64);

        const hashBytes = await sha256(disclosureB64);
        sdHashes.push(bytesToBase64url(hashBytes));
    }

    // Build issuer JWT payload
    const now = Math.floor(Date.now() / 1000);
    const payload: Record<string, unknown> = {
        iss: 'https://issuer.de/eudi',
        vct: 'urn:eu.europa.ec.eudi:pid:1',
        ...claims,
        exp: now + expSeconds,
        iat: now,
    };

    if (sdHashes.length > 0) {
        payload._sd_alg = 'sha-256';
        payload._sd = sdHashes;
    }

    // Add holder key binding reference if holder key provided
    if (holderKey) {
        const holderJwk = await crypto.subtle.exportKey('jwk', holderKey.publicKey);
        delete holderJwk.d; // strip private component
        payload.cnf = { jwk: holderJwk };
    }

    // Sign issuer JWT
    const issuerJwt = await new jose.SignJWT(payload as jose.JWTPayload)
        .setProtectedHeader({ alg, typ, x5c: [issuerKey.x5cBase64] })
        .sign(issuerKey.privateKey);

    // Assemble SD-JWT: issuerJwt~disc1~disc2~...~
    const disclosurePart = disclosures.length > 0 ? disclosures.join('~') + '~' : '';
    let sdJwt = issuerJwt + '~' + disclosurePart;
    let kbJwt: string | undefined;

    // Add KB-JWT if holder key and nonce provided
    if (holderKey && nonce) {
        const sdJwtForHash = sdJwt;
        const sdHashBytes = await sha256(sdJwtForHash);
        const sdHashB64 = bytesToBase64url(sdHashBytes);

        const kbPayload: jose.JWTPayload = {
            iat: now,
            nonce,
            sd_hash: sdHashB64,
        };
        if (audience) {
            kbPayload.aud = audience;
        }

        kbJwt = await new jose.SignJWT(kbPayload).setProtectedHeader({ alg, typ: 'kb+jwt' }).sign(holderKey.privateKey);

        sdJwt += kbJwt;
    }

    return { sdJwt, issuerJwt, disclosures, kbJwt, sdHashes };
}

// ----------------------------------------------------------------
// PEM helpers
// ----------------------------------------------------------------

/** Convert a base64-encoded DER certificate to PEM format. */
export function derToPem(base64Der: string): string {
    const lines = base64Der.match(/.{1,64}/g) || [];
    return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----`;
}

// ----------------------------------------------------------------
// Tampering helpers (for negative test cases)
// ----------------------------------------------------------------

/** Modify JWT payload claims without re-signing — produces an invalid signature. */
export function tamperJwtPayload(jwt: string, changes: Record<string, unknown>): string {
    const [header, payload, signature] = jwt.split('.');
    const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString());
    Object.assign(decoded, changes);
    const tampered = Buffer.from(JSON.stringify(decoded)).toString('base64url');
    return `${header}.${tampered}.${signature}`;
}

/** Build a structurally valid but cryptographically unsigned JWT (fake signature). */
export function buildStaticJwt(header: Record<string, unknown>, payload: Record<string, unknown>): string {
    const h = Buffer.from(JSON.stringify(header)).toString('base64url');
    const p = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const s = Buffer.from('fake-signature').toString('base64url');
    return `${h}.${p}.${s}`;
}

// ----------------------------------------------------------------
// Internal helpers
// ----------------------------------------------------------------

function base64urlEncodeString(input: string): string {
    return Buffer.from(input, 'utf-8').toString('base64url');
}

function bytesToBase64url(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString('base64url');
}

async function sha256(input: string): Promise<Uint8Array> {
    const data = new TextEncoder().encode(input);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return new Uint8Array(hash);
}

// -----------------------------------------------------------------------------
// Helpers for workstream B-remaining (OIDF verifier test features).
// -----------------------------------------------------------------------------

import * as x509 from '@peculiar/x509';
import { CompactEncrypt } from 'jose';

export interface VerifierKeyMaterial {
    signer: CryptoKeyPair;
    certificateChain: Uint8Array[];
    hostname: string;
}

export async function createVerifierKeypairAndCert(hostname: string): Promise<VerifierKeyMaterial> {
    const signer = (await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify']
    )) as CryptoKeyPair;

    const cert = await x509.X509CertificateGenerator.createSelfSigned({
        serialNumber: '01',
        name: `CN=${hostname}`,
        notBefore: new Date(Date.now() - 60_000),
        notAfter: new Date(Date.now() + 3600_000),
        signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
        keys: signer,
        extensions: [
            new x509.SubjectAlternativeNameExtension([{ type: 'dns', value: hostname }]),
        ],
    });

    const certDer = new Uint8Array(cert.rawData);
    return { signer, certificateChain: [certDer], hostname };
}

export interface EncryptionKeypair {
    publicJwk: JsonWebKey;
    privateKey: CryptoKey;
}

export async function createEncryptionKeypair(
    alg: 'ECDH-ES' = 'ECDH-ES'
): Promise<EncryptionKeypair> {
    const keyPair = (await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        ['deriveBits', 'deriveKey']
    )) as CryptoKeyPair;
    const publicJwk = (await crypto.subtle.exportKey('jwk', keyPair.publicKey)) as JsonWebKey;
    publicJwk.alg = alg;
    publicJwk.use = 'enc';
    return { publicJwk, privateKey: keyPair.privateKey };
}

export function createVpFormatsSupported(): Record<string, unknown> {
    return {
        'dc+sd-jwt': {
            'sd-jwt_alg_values': ['ES256'],
        },
    };
}

export async function encryptAuthorizationResponseJwe(
    payload: Record<string, unknown>,
    recipientPublicJwk: JsonWebKey,
    enc: 'A128GCM' | 'A256GCM' = 'A256GCM'
): Promise<string> {
    const alg = (recipientPublicJwk.alg as 'ECDH-ES') ?? 'ECDH-ES';
    const recipientKey = await crypto.subtle.importKey(
        'jwk',
        recipientPublicJwk,
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        []
    );
    return new CompactEncrypt(new TextEncoder().encode(JSON.stringify(payload)))
        .setProtectedHeader({ alg, enc })
        .encrypt(recipientKey);
}
