/**
 * Low-level SD-JWT VC builder for negative tests: every field of the issuer
 * JWT, the disclosures and the KB-JWT can be set or left out. Signs with real
 * ES256 keys through jose and is verified via `trustedIssuerJwks` (no x5c).
 */

import * as jose from 'jose';

export type SdAlg = 'sha-256' | 'sha-384' | 'sha-512' | (string & {});

const WEB_CRYPTO_HASH: Record<string, string> = {
    'sha-256': 'SHA-256',
    'sha-384': 'SHA-384',
    'sha-512': 'SHA-512',
};

export const b64u = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64url');

export async function digest(alg: SdAlg, input: string): Promise<string> {
    const webAlg = WEB_CRYPTO_HASH[alg] ?? 'SHA-256';
    return b64u(new Uint8Array(await crypto.subtle.digest(webAlg, new TextEncoder().encode(input))));
}

export function encodeDisclosure(name: string, value: unknown): string {
    const salt = b64u(crypto.getRandomValues(new Uint8Array(16)));
    return b64u(new TextEncoder().encode(JSON.stringify([salt, name, value])));
}

export interface TestKeys {
    issuer: CryptoKeyPair;
    issuerJwk: JsonWebKey;
    holder: CryptoKeyPair;
    holderJwk: jose.JWK;
}

export async function generateKeys(): Promise<TestKeys> {
    const issuer = (await jose.generateKeyPair('ES256', { extractable: true })) as CryptoKeyPair;
    const holder = (await jose.generateKeyPair('ES256', { extractable: true })) as CryptoKeyPair;
    return {
        issuer,
        issuerJwk: (await jose.exportJWK(issuer.publicKey)) as JsonWebKey,
        holder,
        holderJwk: await jose.exportJWK(holder.publicKey),
    };
}

export interface IssueOptions {
    /** Selectively disclosable top-level claims. */
    claims?: Record<string, unknown>;
    /** Extra issuer-signed payload members (override defaults). */
    payload?: Record<string, unknown>;
    /** Put `cnf.jwk` (the holder key) into the payload. Default true. */
    holderBound?: boolean;
    /** `_sd_alg`; `null` omits the claim. Default 'sha-256'. */
    sdAlg?: SdAlg | null;
    /** Pre-encoded disclosures to use instead of encoding `claims`. */
    disclosures?: string[];
    /** Digests for `_sd` instead of the disclosures' own digests. */
    sdDigests?: string[];
}

export interface Issued {
    jwt: string;
    disclosures: string[];
    /** `jwt~d1~…~dn~` — the presentation without a KB-JWT. */
    presentation: string;
}

export async function issue(keys: TestKeys, opts: IssueOptions = {}): Promise<Issued> {
    const sdAlg = opts.sdAlg === undefined ? 'sha-256' : opts.sdAlg;
    const disclosures =
        opts.disclosures ?? Object.entries(opts.claims ?? {}).map(([k, v]) => encodeDisclosure(k, v));
    const sd = opts.sdDigests ?? (await Promise.all(disclosures.map((d) => digest(sdAlg ?? 'sha-256', d))));
    const now = Math.floor(Date.now() / 1000);
    const payload: Record<string, unknown> = {
        iss: 'https://issuer.example',
        vct: 'urn:eudi:pid:1',
        iat: now,
        exp: now + 3600,
        _sd: sd,
        ...(sdAlg !== null ? { _sd_alg: sdAlg } : {}),
        ...(opts.holderBound === false ? {} : { cnf: { jwk: keys.holderJwk } }),
        ...opts.payload,
    };
    const jwt = await new jose.SignJWT(payload as jose.JWTPayload)
        .setProtectedHeader({ alg: 'ES256', typ: 'dc+sd-jwt' })
        .sign(keys.issuer.privateKey);
    return { jwt, disclosures, presentation: `${jwt}~${disclosures.map((d) => `${d}~`).join('')}` };
}

export interface KbJwtOptions {
    nonce?: string;
    aud?: unknown;
    /** `null` omits the header parameter. Default 'kb+jwt'. */
    typ?: string | null;
    /** Seconds since epoch; `null` omits the claim. Default now. */
    iat?: number | null;
    /** `null` omits the claim; default is the correct hash. */
    sdHash?: string | null;
    /** Hash algorithm for the default `sd_hash`. Default 'sha-256'. */
    sdAlg?: SdAlg;
}

/** Appends a KB-JWT signed with the holder key to `presentation`. */
export async function withKbJwt(keys: TestKeys, presentation: string, opts: KbJwtOptions = {}): Promise<string> {
    const payload: Record<string, unknown> = {};
    if (opts.nonce !== undefined) payload.nonce = opts.nonce;
    if (opts.aud !== undefined) payload.aud = opts.aud;
    if (opts.iat !== null) payload.iat = opts.iat ?? Math.floor(Date.now() / 1000);
    if (opts.sdHash !== null) payload.sd_hash = opts.sdHash ?? (await digest(opts.sdAlg ?? 'sha-256', presentation));
    const header: jose.JWTHeaderParameters = { alg: 'ES256' };
    if (opts.typ !== null) header.typ = opts.typ ?? 'kb+jwt';
    const kb = await new jose.SignJWT(payload as jose.JWTPayload).setProtectedHeader(header).sign(keys.holder.privateKey);
    return presentation + kb;
}

/** A random date of birth in the 1950–1999 range, as an ISO date string. */
export function randomBirthdate(): string {
    const year = 1950 + Math.floor(Math.random() * 50);
    const month = String(1 + Math.floor(Math.random() * 12)).padStart(2, '0');
    const day = String(1 + Math.floor(Math.random() * 28)).padStart(2, '0');
    return `${year}-${month}-${day}`;
}
