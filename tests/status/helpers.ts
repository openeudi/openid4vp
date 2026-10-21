import { randomInt, randomUUID } from 'node:crypto';
import { deflateSync } from 'node:zlib';

import * as jose from 'jose';
import * as x509 from '@peculiar/x509';
import { Crypto as PeculiarCrypto } from '@peculiar/webcrypto';

import type { Fetcher } from '../../src/trust/Fetcher.js';
import type { TestKeyMaterial } from '../fixtures/crypto-helpers.js';
import { StaticTrustStore } from '../../src/trust/TrustStore.js';
import { createCa, createIntermediate, createLeaf, type GeneratedCa } from '../trust/helpers/synthetic-ca.js';

const peculiar = new PeculiarCrypto();

export interface StatusListSigner {
    root: GeneratedCa;
    /** Base64 DER chain for the JWS `x5c` header, signer first (root excluded). */
    x5c: string[];
    signingKey: CryptoKey | Uint8Array;
    /** Trust store holding only the root. */
    trustStore: StaticTrustStore;
    leafDer: Uint8Array;
}

function toB64(cert: x509.X509Certificate): string {
    return Buffer.from(new Uint8Array(cert.rawData)).toString('base64');
}

/** Root CA → (optional intermediate) → status-list signer leaf. */
export async function createStatusListSigner(opts: { intermediate?: boolean } = {}): Promise<StatusListSigner> {
    // Backdated so tokens with an `iat` in the past are signed within validity.
    const notBefore = new Date(Date.now() - 30 * 86_400_000);
    const root = await createCa({ name: `CN=Status Root ${randomUUID()}`, notBefore });
    const parent = opts.intermediate
        ? await createIntermediate(root, { name: `CN=Status Sub CA ${randomUUID()}`, notBefore })
        : root;
    const leaf = await createLeaf(parent, { name: `CN=Status List Signer ${randomUUID()}`, notBefore });
    // Keys from @peculiar/webcrypto are not accepted by jose under Node; round-trip via JWK.
    const jwk = await peculiar.subtle.exportKey('jwk', leaf.keys.privateKey);
    const signingKey = (await jose.importJWK(jwk as jose.JWK, 'ES256')) as CryptoKey;
    const x5c = opts.intermediate ? [toB64(leaf.certificate), toB64(parent.certificate)] : [toB64(leaf.certificate)];
    return {
        root,
        x5c,
        signingKey,
        trustStore: new StaticTrustStore([root.certificate]),
        leafDer: new Uint8Array(leaf.certificate.rawData),
    };
}

export function rootB64(signer: StatusListSigner): string {
    return toB64(signer.root.certificate);
}

/** Packs status values LSB-first per draft-ietf-oauth-status-list-21 §4.1. */
export function packStatuses(bits: 1 | 2 | 4 | 8, values: readonly number[]): Uint8Array {
    const perByte = 8 / bits;
    const out = new Uint8Array(Math.ceil(values.length / perByte));
    values.forEach((v, i) => {
        out[Math.floor(i / perByte)] |= (v & ((1 << bits) - 1)) << ((i % perByte) * bits);
    });
    return out;
}

export function compressToLst(bytes: Uint8Array): string {
    return jose.base64url.encode(deflateSync(bytes, { level: 9 }));
}

export function randomStatuses(bits: 1 | 2 | 4 | 8, count: number): number[] {
    return Array.from({ length: count }, () => randomInt(0, 1 << bits));
}

export function randomStatusUri(): string {
    return `https://status-${randomInt(1, 1_000_000)}.example.eu/lists/${randomUUID()}`;
}

export interface BuildStatusListJwtOptions {
    signer: StatusListSigner;
    uri: string;
    bits?: 1 | 2 | 4 | 8;
    statuses?: readonly number[];
    /** Overrides / removals (value `undefined`) applied to the payload. */
    claims?: Record<string, unknown>;
    header?: Record<string, unknown>;
    nowSeconds?: number;
}

export async function buildStatusListJwt(opts: BuildStatusListJwtOptions): Promise<string> {
    const bits = opts.bits ?? 2;
    const now = opts.nowSeconds ?? Math.floor(Date.now() / 1000);
    const payload: Record<string, unknown> = {
        sub: opts.uri,
        iat: now - 10,
        exp: now + 3600,
        ttl: 600,
        status_list: { bits, lst: compressToLst(packStatuses(bits, opts.statuses ?? [0, 1, 2, 0])) },
    };
    for (const [k, v] of Object.entries(opts.claims ?? {})) {
        if (v === undefined) delete payload[k];
        else payload[k] = v;
    }
    const header = { alg: 'ES256', typ: 'statuslist+jwt', x5c: opts.signer.x5c, ...(opts.header ?? {}) };
    return new jose.CompactSign(new TextEncoder().encode(JSON.stringify(payload)))
        .setProtectedHeader(header as jose.CompactJWSHeaderParameters)
        .sign(opts.signer.signingKey);
}

export type StubResponse = { status?: number; body: string } | Error;

export interface StubFetcher {
    fetcher: Fetcher;
    calls: Array<{ url: string; init?: RequestInit }>;
    set(url: string, response: StubResponse): void;
}

/** In-memory fetcher; an unknown URL responds 404. No network. */
export function createStubFetcher(initial: Record<string, StubResponse> = {}): StubFetcher {
    const routes = new Map<string, StubResponse>(Object.entries(initial));
    const calls: StubFetcher['calls'] = [];
    const fetcher: Fetcher = async (url, init) => {
        calls.push({ url, init });
        const route = routes.get(url);
        if (!route) return new Response('not found', { status: 404 });
        if (route instanceof Error) throw route;
        return new Response(route.body, {
            status: route.status ?? 200,
            headers: { 'content-type': 'application/statuslist+jwt' },
        });
    };
    return { fetcher, calls, set: (url, response) => routes.set(url, response) };
}

/** A mutable clock for cache / time-claim tests. */
export function createClock(start: Date = new Date()): { now: () => Date; advance(seconds: number): void } {
    let t = start.getTime();
    return {
        now: () => new Date(t),
        advance(seconds: number) {
            t += seconds * 1000;
        },
    };
}

async function toNativeKey(key: CryptoKey, usage: 'sign' | 'verify'): Promise<CryptoKey> {
    const jwk = await peculiar.subtle.exportKey('jwk', key);
    return crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, [usage]);
}

/**
 * Credential issuer key material for `buildSignedSdJwt`. Built on the
 * synthetic CA (this module sets the @peculiar/x509 provider process-wide,
 * which `generateTestKeyMaterial` does not tolerate), with the keys moved to
 * Node's native WebCrypto so jose can use them.
 */
export async function createIssuerKeyMaterial(): Promise<TestKeyMaterial> {
    const ca = await createCa({ name: `CN=PID Issuer CA ${randomUUID()}`, notBefore: new Date(Date.now() - 86_400_000) });
    const leaf = await createLeaf(ca, { name: `CN=PID Issuer ${randomUUID()}`, notBefore: new Date(Date.now() - 86_400_000) });
    const der = new Uint8Array(leaf.certificate.rawData);
    return {
        privateKey: await toNativeKey(leaf.keys.privateKey, 'sign'),
        publicKey: await toNativeKey(leaf.keys.publicKey, 'verify'),
        x5cBase64: Buffer.from(der).toString('base64'),
        certDerBytes: der,
    };
}

/** Holder key material: only the key pair is used (cnf.jwk + KB-JWT). */
export async function createHolderKeyMaterial(): Promise<TestKeyMaterial> {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    return { privateKey: pair.privateKey, publicKey: pair.publicKey, x5cBase64: '', certDerBytes: new Uint8Array() };
}
