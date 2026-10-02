/**
 * IACA → Document Signer → credential chain building (EID-151).
 *
 * The EU PID-providers list (ETSI TS 119 602 LoTE) publishes, for most
 * providers, an IACA root rather than the document-signer (DS) certificate
 * that actually signs the PID. These tests pin down that a credential whose
 * signer chains to an anchor verifies, that a signer which IS the listed
 * anchor still verifies (direct match), and that everything else fails closed.
 */
import { Crypto as PeculiarCrypto } from '@peculiar/webcrypto';
import { KeyUsageFlags, type X509Certificate } from '@peculiar/x509';
import { SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';

import { CertificateChainError, TrustAnchorNotFoundError } from '../../src/errors.js';
import { MdocParser } from '../../src/parsers/mdoc.parser.js';
import type { ParseOptions } from '../../src/parsers/parser.interface.js';
import { SdJwtParser } from '../../src/parsers/sd-jwt.parser.js';
import { ChainBuilder, ISO_18013_5_DS_EKU } from '../../src/trust/ChainBuilder.js';
import { TrustEvaluator } from '../../src/trust/TrustEvaluator.js';
import { StaticTrustStore } from '../../src/trust/TrustStore.js';
import { certificatesEqual } from '../../src/trust/x509-utils.js';
import { buildSignedSdJwt, type TestKeyMaterial } from '../fixtures/crypto-helpers.js';
import { buildSignedMdoc } from '../fixtures/mdoc-helpers.js';
import {
    createCa,
    createIntermediate,
    createLeaf,
    createSelfSigned,
    type GeneratedCa,
    type Leaf,
} from './helpers/synthetic-ca.js';

const peculiar = new PeculiarCrypto();
const HOUR = 3600 * 1000;
const DAY = 24 * HOUR;

function uniqueName(role: string): string {
    return `CN=${role} ${crypto.randomUUID()},O=Member State PID Provider,C=EU`;
}

async function createIaca(opts: { name?: string; serialNumber?: string } = {}): Promise<GeneratedCa> {
    // ISO 18013-5 Annex B: IACA is a self-signed root with pathLenConstraint 0.
    // Long-lived and back-dated so issuance-time checks isolate the DS.
    return createCa({
        name: opts.name ?? uniqueName('IACA'),
        pathLenConstraint: 0,
        serialNumber: opts.serialNumber,
        notBefore: new Date(Date.now() - 365 * 24 * 3600 * 1000),
    });
}

async function createDs(
    issuer: GeneratedCa,
    opts: Parameters<typeof createLeaf>[1] = {}
): Promise<Leaf> {
    return createLeaf(issuer, {
        name: uniqueName('Document Signer'),
        extendedKeyUsages: [ISO_18013_5_DS_EKU],
        ...opts,
    });
}

/** @peculiar/webcrypto keys → Node WebCrypto keys, so jose / the mdoc fixture can sign. */
async function toKeyMaterial(leaf: Leaf): Promise<TestKeyMaterial> {
    const jwkPriv = await peculiar.subtle.exportKey('jwk', leaf.keys.privateKey);
    const jwkPub = await peculiar.subtle.exportKey('jwk', leaf.keys.publicKey);
    const algo = { name: 'ECDSA', namedCurve: 'P-256' };
    const der = new Uint8Array(leaf.certificate.rawData);
    return {
        privateKey: await crypto.subtle.importKey('jwk', jwkPriv, algo, true, ['sign']),
        publicKey: await crypto.subtle.importKey('jwk', jwkPub, algo, true, ['verify']),
        x5cBase64: Buffer.from(der).toString('base64'),
        certDerBytes: der,
    };
}

function der(cert: X509Certificate): Uint8Array {
    return new Uint8Array(cert.rawData);
}

function b64(cert: X509Certificate): string {
    return Buffer.from(der(cert)).toString('base64');
}

// ---------------------------------------------------------------------------
// ChainBuilder
// ---------------------------------------------------------------------------

describe('ChainBuilder — IACA → DS (ISO 18013-5 profile)', () => {
    const iso = () => new ChainBuilder({ profile: 'iso18013-5' });

    it('accepts a DS issued by the IACA anchor', async () => {
        const iaca = await createIaca();
        const ds = await createDs(iaca);
        const chain = await iso().build(ds.certificate, [iaca.certificate]);
        expect(chain).toHaveLength(2);
        expect(certificatesEqual(chain[1], iaca.certificate)).toBe(true);
    });

    it('accepts when the wallet also ships the IACA itself in x5chain', async () => {
        const iaca = await createIaca();
        const ds = await createDs(iaca);
        const chain = await iso().build(ds.certificate, [iaca.certificate], [iaca.certificate]);
        expect(chain).toHaveLength(2);
    });

    it('rejects a DS lacking the mdlDS extended key usage', async () => {
        const iaca = await createIaca();
        const ds = await createDs(iaca, { extendedKeyUsages: [] });
        await expect(iso().build(ds.certificate, [iaca.certificate])).rejects.toMatchObject({
            code: 'chain_invalid',
            reason: 'extended_key_usage',
        });
    });

    it('rejects a DS whose extended key usage names a different purpose', async () => {
        const iaca = await createIaca();
        const ds = await createDs(iaca, { extendedKeyUsages: ['1.3.6.1.5.5.7.3.2'] });
        await expect(iso().build(ds.certificate, [iaca.certificate])).rejects.toMatchObject({
            reason: 'extended_key_usage',
        });
    });

    it('rejects a DS without any keyUsage extension', async () => {
        const iaca = await createIaca();
        const ds = await createDs(iaca, { omitKeyUsage: true });
        await expect(iso().build(ds.certificate, [iaca.certificate])).rejects.toMatchObject({
            reason: 'key_usage',
        });
    });

    it('does not require the mdlDS EKU under the generic (SD-JWT VC) profile', async () => {
        const iaca = await createIaca();
        const ds = await createDs(iaca, { extendedKeyUsages: [] });
        await expect(new ChainBuilder().build(ds.certificate, [iaca.certificate])).resolves.toHaveLength(2);
    });

    it('rejects an IACA that permits no intermediates when one is inserted (pathLenConstraint 0)', async () => {
        const iaca = await createIaca();
        const intermediate = await createIntermediate(iaca, { name: uniqueName('Sub CA') });
        const ds = await createDs(intermediate);
        await expect(
            iso().build(ds.certificate, [iaca.certificate], [intermediate.certificate])
        ).rejects.toMatchObject({ reason: 'path_length' });
    });
});

describe('ChainBuilder — CA constraints on intermediates', () => {
    it('rejects an intermediate whose basicConstraints cA=false', async () => {
        const root = await createCa({ name: uniqueName('Root') });
        const notCa = await createIntermediate(root, { name: uniqueName('Not A CA'), isCa: false });
        const ds = await createDs(notCa);
        await expect(
            new ChainBuilder().build(ds.certificate, [root.certificate], [notCa.certificate])
        ).rejects.toMatchObject({ code: 'chain_invalid', reason: 'basic_constraints' });
    });

    it('rejects an intermediate without keyCertSign', async () => {
        const root = await createCa({ name: uniqueName('Root') });
        const noSign = await createIntermediate(root, {
            name: uniqueName('No keyCertSign'),
            keyUsage: KeyUsageFlags.digitalSignature,
        });
        const ds = await createDs(noSign);
        await expect(
            new ChainBuilder().build(ds.certificate, [root.certificate], [noSign.certificate])
        ).rejects.toMatchObject({ reason: 'key_usage' });
    });

    it('rejects a DS without digitalSignature key usage', async () => {
        const iaca = await createIaca();
        const ds = await createDs(iaca, { keyUsage: KeyUsageFlags.keyEncipherment });
        await expect(new ChainBuilder().build(ds.certificate, [iaca.certificate])).rejects.toMatchObject({
            reason: 'key_usage',
        });
    });
});

describe('ChainBuilder — chain length and loops', () => {
    async function deepChain(intermediateCount: number) {
        const root = await createCa({ name: uniqueName('Root') });
        const intermediates: GeneratedCa[] = [];
        let parent = root;
        for (let i = 0; i < intermediateCount; i++) {
            parent = await createIntermediate(parent, { name: uniqueName(`Sub CA ${i}`) });
            intermediates.push(parent);
        }
        const leaf = await createDs(parent);
        return { root, intermediates: intermediates.map((c) => c.certificate), leaf: leaf.certificate };
    }

    it('accepts a chain at the default maximum length (5 certificates)', async () => {
        const { root, intermediates, leaf } = await deepChain(3);
        await expect(new ChainBuilder().build(leaf, [root.certificate], intermediates)).resolves.toHaveLength(5);
    });

    it('rejects a chain longer than the default maximum', async () => {
        const { root, intermediates, leaf } = await deepChain(4);
        await expect(new ChainBuilder().build(leaf, [root.certificate], intermediates)).rejects.toMatchObject({
            reason: 'path_length',
        });
    });

    it('honours a caller-supplied maxChainLength', async () => {
        const { root, intermediates, leaf } = await deepChain(2);
        await expect(
            new ChainBuilder({ maxChainLength: 3 }).build(leaf, [root.certificate], intermediates)
        ).rejects.toMatchObject({ reason: 'path_length' });
    });

    it('terminates on a self-issued non-anchor in the pool instead of looping', async () => {
        const root = await createCa({ name: uniqueName('Root') });
        const loopName = uniqueName('Loop CA');
        const loop = await createSelfSigned({ name: loopName, isCa: true, keyUsage: KeyUsageFlags.keyCertSign });
        const leaf = await createLeaf(loop, { name: uniqueName('Leaf') });
        await expect(
            new ChainBuilder().build(leaf.certificate, [root.certificate], [loop.certificate, loop.certificate])
        ).rejects.toBeInstanceOf(CertificateChainError);
    });
});

describe('ChainBuilder — validity at verification and issuance time', () => {
    it('rejects an expired DS', async () => {
        const iaca = await createIaca();
        const ds = await createDs(iaca, {
            notBefore: new Date(Date.now() - 30 * DAY),
            notAfter: new Date(Date.now() - DAY),
        });
        await expect(new ChainBuilder().build(ds.certificate, [iaca.certificate])).rejects.toMatchObject({
            reason: 'validity',
        });
    });

    it('rejects a DS that was not yet valid when the credential was issued', async () => {
        const iaca = await createIaca();
        const ds = await createDs(iaca, { notBefore: new Date(Date.now() - HOUR) });
        const issuedAt = new Date(Date.now() - 2 * DAY);
        await expect(
            new ChainBuilder().build(ds.certificate, [iaca.certificate], [], { issuedAt })
        ).rejects.toMatchObject({ reason: 'validity' });
    });

    it('accepts when the chain was valid at issuance time', async () => {
        const iaca = await createIaca();
        const ds = await createDs(iaca, { notBefore: new Date(Date.now() - 2 * DAY) });
        const issuedAt = new Date(Date.now() - DAY);
        await expect(
            new ChainBuilder().build(ds.certificate, [iaca.certificate], [], { issuedAt })
        ).resolves.toHaveLength(2);
    });
});

describe('ChainBuilder — anchors are matched by certificate, never by DN (GHSA-4c2f regression)', () => {
    it('rejects a DS issued by an impostor root that copies the anchor Subject DN', async () => {
        const anchorName = uniqueName('IACA');
        const realIaca = await createIaca({ name: anchorName });
        const impostor = await createIaca({ name: anchorName }); // same DN, different key
        const ds = await createDs(impostor);
        await expect(
            new ChainBuilder({ profile: 'iso18013-5' }).build(ds.certificate, [realIaca.certificate], [impostor.certificate])
        ).rejects.toBeInstanceOf(CertificateChainError);
        await expect(
            new ChainBuilder({ profile: 'iso18013-5' }).build(ds.certificate, [realIaca.certificate])
        ).rejects.toBeInstanceOf(CertificateChainError);
    });

    it('closes at the real anchor even when an impostor with the same DN is also in the pool', async () => {
        const anchorName = uniqueName('IACA');
        const realIaca = await createIaca({ name: anchorName });
        const impostor = await createIaca({ name: anchorName });
        const ds = await createDs(realIaca);
        const chain = await new ChainBuilder().build(ds.certificate, [realIaca.certificate], [impostor.certificate]);
        expect(certificatesEqual(chain[chain.length - 1], realIaca.certificate)).toBe(true);
    });
});

// ---------------------------------------------------------------------------
// TrustEvaluator
// ---------------------------------------------------------------------------

describe('TrustEvaluator — anchor selection', () => {
    it('trusts a DS that is itself the listed anchor (direct match, not self-signed)', async () => {
        const iaca = await createIaca();
        const ds = await createDs(iaca, { extendedKeyUsages: [] });
        // Only the DS is listed — its issuer is unknown to the verifier.
        const evaluator = new TrustEvaluator({
            trustStore: new StaticTrustStore([ds.certificate]),
            profile: 'iso18013-5',
        });
        const result = await evaluator.evaluate(ds.certificate);
        expect(result.chain).toHaveLength(1);
        expect(certificatesEqual(result.anchor.certificate, ds.certificate)).toBe(true);
    });

    it('does not trust a DS whose Subject DN merely matches a listed certificate', async () => {
        const iaca = await createIaca();
        const listed = await createDs(iaca);
        const lookalike = await createDs(iaca, { name: listed.certificate.subject });
        const evaluator = new TrustEvaluator({ trustStore: new StaticTrustStore([listed.certificate]) });
        await expect(evaluator.evaluate(lookalike.certificate)).rejects.toBeInstanceOf(CertificateChainError);
    });

    it('rejects a DS from a root that is not in the store', async () => {
        const iaca = await createIaca();
        const otherRoot = await createIaca();
        const ds = await createDs(otherRoot);
        const evaluator = new TrustEvaluator({ trustStore: new StaticTrustStore([iaca.certificate]) });
        await expect(evaluator.evaluate(ds.certificate)).rejects.toBeInstanceOf(TrustAnchorNotFoundError);
    });

    it('keeps distinct anchors that happen to share a serial number', async () => {
        const serialNumber = Array.from(crypto.getRandomValues(new Uint8Array(8)), (b) =>
            b.toString(16).padStart(2, '0')
        ).join('');
        const name = uniqueName('IACA');
        const first = await createIaca({ name, serialNumber });
        const second = await createIaca({ name, serialNumber });
        const ds = await createDs(second);
        const evaluator = new TrustEvaluator({
            trustStore: new StaticTrustStore([first.certificate, second.certificate]),
        });
        const result = await evaluator.evaluate(ds.certificate);
        expect(certificatesEqual(result.anchor.certificate, second.certificate)).toBe(true);
    });
});

// ---------------------------------------------------------------------------
// Parsers end-to-end
// ---------------------------------------------------------------------------

function storeOptions(certs: X509Certificate[], overrides: Partial<ParseOptions> = {}): ParseOptions {
    return {
        trustedCertificates: [],
        trustStore: new StaticTrustStore(certs),
        nonce: crypto.randomUUID(),
        ...overrides,
    };
}

/** Holder device key on Node WebCrypto; the mdoc fixture never reads its certificate. */
async function nodeDeviceKey(): Promise<TestKeyMaterial> {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    return { privateKey: pair.privateKey, publicKey: pair.publicKey, x5cBase64: '', certDerBytes: new Uint8Array() };
}

async function mdocSignedBy(ds: Leaf, opts: { x5chain?: X509Certificate[]; signed?: Date } = {}) {
    const issuerKey = await toKeyMaterial(ds);
    const signed = opts.signed ?? new Date();
    return buildSignedMdoc({
        issuerKey,
        deviceKey: await nodeDeviceKey(),
        namespaces: { 'eu.europa.ec.eudi.pid.1': { birth_date: '1990-01-01', family_name: crypto.randomUUID() } },
        signed,
        validFrom: new Date(signed.getTime() - HOUR),
        x5chain: opts.x5chain?.map(der),
    });
}

describe('MdocParser — IACA chain building', () => {
    const parser = new MdocParser();

    it('verifies a PID whose DS chains to the IACA anchor', async () => {
        const iaca = await createIaca();
        const ds = await createDs(iaca);
        const mdoc = await mdocSignedBy(ds);
        const result = await parser.parse(
            mdoc.mdocBytes,
            storeOptions([iaca.certificate], { mdocSessionTranscript: mdoc.sessionTranscript })
        );
        expect(result.error).toBeUndefined();
        expect(result.valid).toBe(true);
        expect(result.trust?.chain).toHaveLength(2);
    });

    it('verifies when the x5chain carries DS + IACA', async () => {
        const iaca = await createIaca();
        const ds = await createDs(iaca);
        const mdoc = await mdocSignedBy(ds, { x5chain: [ds.certificate, iaca.certificate] });
        const result = await parser.parse(
            mdoc.mdocBytes,
            storeOptions([iaca.certificate], { mdocSessionTranscript: mdoc.sessionTranscript })
        );
        expect(result.valid).toBe(true);
    });

    it('still verifies when the listed certificate is the DS itself (direct match)', async () => {
        const iaca = await createIaca();
        const ds = await createDs(iaca);
        const mdoc = await mdocSignedBy(ds);
        const result = await parser.parse(
            mdoc.mdocBytes,
            storeOptions([ds.certificate], { mdocSessionTranscript: mdoc.sessionTranscript })
        );
        expect(result.valid).toBe(true);
        expect(result.trust?.chain).toHaveLength(1);
    });

    it('rejects a DS issued by a different root', async () => {
        const iaca = await createIaca();
        const otherRoot = await createIaca();
        const ds = await createDs(otherRoot);
        const mdoc = await mdocSignedBy(ds, { x5chain: [ds.certificate, otherRoot.certificate] });
        await expect(
            parser.parse(mdoc.mdocBytes, storeOptions([iaca.certificate], { mdocSessionTranscript: mdoc.sessionTranscript }))
        ).rejects.toThrow();
    });

    it('rejects a DS without the mdlDS EKU', async () => {
        const iaca = await createIaca();
        const ds = await createDs(iaca, { extendedKeyUsages: [] });
        const mdoc = await mdocSignedBy(ds);
        await expect(
            parser.parse(mdoc.mdocBytes, storeOptions([iaca.certificate], { mdocSessionTranscript: mdoc.sessionTranscript }))
        ).rejects.toMatchObject({ reason: 'extended_key_usage' });
    });

    it('rejects an expired DS', async () => {
        const iaca = await createIaca();
        const ds = await createDs(iaca, {
            notBefore: new Date(Date.now() - 30 * DAY),
            notAfter: new Date(Date.now() - DAY),
        });
        const mdoc = await mdocSignedBy(ds, { signed: new Date(Date.now() - 2 * DAY) });
        await expect(
            parser.parse(mdoc.mdocBytes, storeOptions([iaca.certificate], { mdocSessionTranscript: mdoc.sessionTranscript }))
        ).rejects.toMatchObject({ reason: 'validity' });
    });

    it('rejects an MSO signed before the DS became valid', async () => {
        const iaca = await createIaca();
        const ds = await createDs(iaca, { notBefore: new Date(Date.now() - HOUR) });
        const mdoc = await mdocSignedBy(ds, { signed: new Date(Date.now() - DAY) });
        await expect(
            parser.parse(mdoc.mdocBytes, storeOptions([iaca.certificate], { mdocSessionTranscript: mdoc.sessionTranscript }))
        ).rejects.toMatchObject({ reason: 'validity' });
    });

    it('rejects an impostor IACA in x5chain that copies the anchor DN (GHSA-4c2f regression)', async () => {
        const anchorName = uniqueName('IACA');
        const realIaca = await createIaca({ name: anchorName });
        const impostor = await createIaca({ name: anchorName });
        const ds = await createDs(impostor);
        const mdoc = await mdocSignedBy(ds, { x5chain: [ds.certificate, impostor.certificate] });
        await expect(
            parser.parse(mdoc.mdocBytes, storeOptions([realIaca.certificate], { mdocSessionTranscript: mdoc.sessionTranscript }))
        ).rejects.toBeInstanceOf(CertificateChainError);
    });
});

async function sdJwtSignedBy(ds: Leaf, x5c: X509Certificate[] = [ds.certificate]): Promise<string> {
    const issuerKey = await toKeyMaterial(ds);
    const built = await buildSignedSdJwt({
        issuerKey,
        claims: { vct: 'urn:eu.europa.ec.eudi:pid:1' },
        disclosureClaims: [['birth_date', '1990-01-01']],
    });
    const [rawHeader, rawPayload] = built.issuerJwt.split('.');
    const header = JSON.parse(Buffer.from(rawHeader, 'base64url').toString());
    const payload = JSON.parse(Buffer.from(rawPayload, 'base64url').toString());
    const reSigned = await new SignJWT(payload)
        .setProtectedHeader({ ...header, x5c: x5c.map(b64) })
        .sign(issuerKey.privateKey);
    return built.sdJwt.replace(built.issuerJwt, reSigned);
}

describe('SdJwtParser — IACA chain building', () => {
    const parser = new SdJwtParser();

    it('verifies a PID whose DS chains to the root anchor (no mdlDS EKU needed)', async () => {
        const root = await createIaca();
        const ds = await createDs(root, { extendedKeyUsages: [] });
        const token = await sdJwtSignedBy(ds);
        const result = await parser.parse(token, storeOptions([root.certificate]));
        expect(result.error).toBeUndefined();
        expect(result.valid).toBe(true);
        expect(result.trust?.chain).toHaveLength(2);
    });

    it('uses x5c intermediates to reach the anchor', async () => {
        const root = await createCa({ name: uniqueName('Root') });
        const intermediate = await createIntermediate(root, { name: uniqueName('Issuing CA') });
        const ds = await createDs(intermediate);
        const token = await sdJwtSignedBy(ds, [ds.certificate, intermediate.certificate]);
        const result = await parser.parse(token, storeOptions([root.certificate]));
        expect(result.valid).toBe(true);
        expect(result.trust?.chain).toHaveLength(3);
    });

    it('still verifies with the DS itself as the anchor (direct match)', async () => {
        const root = await createIaca();
        const ds = await createDs(root);
        const token = await sdJwtSignedBy(ds);
        const result = await parser.parse(token, storeOptions([ds.certificate]));
        expect(result.valid).toBe(true);
    });

    it('rejects a DS from a different root', async () => {
        const root = await createIaca();
        const otherRoot = await createIaca();
        const ds = await createDs(otherRoot);
        const token = await sdJwtSignedBy(ds, [ds.certificate, otherRoot.certificate]);
        await expect(parser.parse(token, storeOptions([root.certificate]))).rejects.toThrow();
    });

    it('rejects an expired DS', async () => {
        const root = await createIaca();
        const ds = await createDs(root, {
            notBefore: new Date(Date.now() - 30 * DAY),
            notAfter: new Date(Date.now() - DAY),
        });
        const token = await sdJwtSignedBy(ds);
        await expect(parser.parse(token, storeOptions([root.certificate]))).rejects.toMatchObject({
            reason: 'validity',
        });
    });

    it('rejects a DS without digitalSignature key usage', async () => {
        const root = await createIaca();
        const ds = await createDs(root, { keyUsage: KeyUsageFlags.keyEncipherment });
        const token = await sdJwtSignedBy(ds);
        await expect(parser.parse(token, storeOptions([root.certificate]))).rejects.toMatchObject({
            reason: 'key_usage',
        });
    });

    it('rejects an impostor root in x5c that copies the anchor DN (GHSA-4c2f regression)', async () => {
        const anchorName = uniqueName('Root');
        const realRoot = await createIaca({ name: anchorName });
        const impostor = await createIaca({ name: anchorName });
        const ds = await createDs(impostor);
        const token = await sdJwtSignedBy(ds, [ds.certificate, impostor.certificate]);
        await expect(parser.parse(token, storeOptions([realRoot.certificate]))).rejects.toBeInstanceOf(
            CertificateChainError
        );
    });

    it('rejects a malformed certificate in x5c', async () => {
        const root = await createIaca();
        const ds = await createDs(root);
        const issuerKey = await toKeyMaterial(ds);
        const built = await buildSignedSdJwt({ issuerKey, claims: { vct: 'urn:eu.europa.ec.eudi:pid:1' } });
        const [rawHeader, rawPayload] = built.issuerJwt.split('.');
        const header = JSON.parse(Buffer.from(rawHeader, 'base64url').toString());
        const payload = JSON.parse(Buffer.from(rawPayload, 'base64url').toString());
        const garbage = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64');
        const reSigned = await new SignJWT(payload)
            .setProtectedHeader({ ...header, x5c: [b64(ds.certificate), garbage] })
            .sign(issuerKey.privateKey);
        const token = built.sdJwt.replace(built.issuerJwt, reSigned);
        await expect(parser.parse(token, storeOptions([root.certificate]))).rejects.toThrow(/x5c/);
    });
});
