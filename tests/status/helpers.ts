import { randomInt, randomUUID } from 'node:crypto';
import { deflateSync } from 'node:zlib';

import { Encoder as CborEncoder, Tag } from 'cbor-x';
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

export interface BuildStatusListCwtOptions {
    signer: StatusListSigner;
    uri: string;
    bits?: 1 | 2 | 4 | 8;
    statuses?: readonly number[];
    /**
     * Overrides / removals (value `undefined`) of CWT claims, by JWT name
     * (`sub`, `iat`, `exp`, `nbf`, `ttl`, `status_list`) or numeric label.
     */
    claims?: Record<string, unknown>;
    /** Overrides / removals of protected header labels (1 alg, 16 typ, 33 x5chain). */
    protectedHeader?: Map<number, unknown>;
    unprotectedHeader?: Map<number, unknown>;
    /** Where x5chain (33) goes. Default `'unprotected'`. */
    x5chainIn?: 'protected' | 'unprotected' | 'both' | 'none';
    /** DER chain, signer first. Default the signer's `x5c`. */
    x5chain?: Uint8Array[];
    /** Outer CBOR tag. Default none. */
    tag?: 'none' | 'cose' | 'cwt';
    nowSeconds?: number;
    /** Change the signed payload after signing. */
    tamper?: boolean;
}

const CWT_LABELS: Record<string, number> = { sub: 2, exp: 4, nbf: 5, iat: 6, status_list: 65533, ttl: 65534 };

const cwtCbor = new CborEncoder({ mapsAsObjects: false, useRecords: false, tagUint8Array: false });

export function x5cToDer(x5c: readonly string[]): Uint8Array[] {
    return x5c.map((c) => new Uint8Array(Buffer.from(c, 'base64')));
}

/** A COSE_Sign1 CWT Status List Token (draft-21 §5.2), really signed by `signer`. */
export async function buildStatusListCwt(opts: BuildStatusListCwtOptions): Promise<Uint8Array> {
    const bits = opts.bits ?? 2;
    const now = opts.nowSeconds ?? Math.floor(Date.now() / 1000);
    const claims = new Map<number, unknown>([
        [2, opts.uri],
        [6, now - 10],
        [4, now + 3600],
        [65534, 600],
        [
            65533,
            new Map<string, unknown>([
                ['bits', bits],
                ['lst', new Uint8Array(deflateSync(packStatuses(bits, opts.statuses ?? [0, 1, 2, 0]), { level: 9 }))],
            ]),
        ],
    ]);
    for (const [k, v] of Object.entries(opts.claims ?? {})) {
        const label = CWT_LABELS[k] ?? Number(k);
        if (v === undefined) claims.delete(label);
        else claims.set(label, v);
    }

    const chain = opts.x5chain ?? x5cToDer(opts.signer.x5c);
    const x5value: unknown = chain.length === 1 ? chain[0] : chain;
    const where = opts.x5chainIn ?? 'unprotected';
    const protectedHeader = new Map<number, unknown>([
        [1, -7],
        [16, 'application/statuslist+cwt'],
    ]);
    const unprotectedHeader = new Map<number, unknown>();
    if (where === 'protected' || where === 'both') protectedHeader.set(33, x5value);
    if (where === 'unprotected' || where === 'both') unprotectedHeader.set(33, x5value);
    for (const [k, v] of opts.protectedHeader ?? []) {
        if (v === undefined) protectedHeader.delete(k);
        else protectedHeader.set(k, v);
    }
    for (const [k, v] of opts.unprotectedHeader ?? []) unprotectedHeader.set(k, v);

    const protectedBytes = new Uint8Array(cwtCbor.encode(protectedHeader));
    const payload = new Uint8Array(cwtCbor.encode(claims));
    const sigInput = new Uint8Array(cwtCbor.encode(['Signature1', protectedBytes, new Uint8Array(0), payload]));
    const signature = new Uint8Array(
        await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, opts.signer.signingKey as CryptoKey, sigInput),
    );
    let signedPayload = payload;
    if (opts.tamper) {
        claims.set(65534, 601);
        signedPayload = new Uint8Array(cwtCbor.encode(claims));
    }
    const cose: unknown[] = [protectedBytes, unprotectedHeader, signedPayload, signature];
    const tag = opts.tag ?? 'none';
    const value = tag === 'none' ? cose : tag === 'cose' ? new Tag(cose, 18) : new Tag(new Tag(cose, 18), 61);
    return new Uint8Array(cwtCbor.encode(value));
}

/** `{ status_list: { idx, uri } }` as a CBOR map, as carried in the mdoc MSO (§6.3). */
export function msoStatus(idx: unknown, uri: unknown): Map<string, unknown> {
    return new Map<string, unknown>([
        [
            'status_list',
            new Map<string, unknown>([
                ['idx', idx],
                ['uri', uri],
            ]),
        ],
    ]);
}

export type StubResponse = { status?: number; body: string | Uint8Array; contentType?: string } | Error;

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
        const isBytes = route.body instanceof Uint8Array;
        return new Response(isBytes ? new Uint8Array(route.body as Uint8Array) : (route.body as string), {
            status: route.status ?? 200,
            headers: {
                'content-type': route.contentType ?? (isBytes ? 'application/statuslist+cwt' : 'application/statuslist+jwt'),
            },
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
