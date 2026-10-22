/**
 * EID-216: extensions are decoded one at a time (src/trust/extensions.ts).
 *
 * @peculiar/x509 2.x decodes every extension on first access, throws on any
 * malformed one and then reports the certificate as extension-less. Here a
 * malformed extension fails closed, except a non-critical IssuerAltName, and
 * one bad certificate never takes a trust store down with it.
 */

import { webcrypto } from 'node:crypto';
import * as x509 from '@peculiar/x509';
import { describe, expect, it } from 'vitest';

import { CertificateChainError } from '../../src/errors.js';
import { ChainBuilder } from '../../src/trust/ChainBuilder.js';
import {
    disqualifyingExtensions,
    malformedExtensions,
    readExtension,
    readTypedExtension,
    unusableAnchorReason,
} from '../../src/trust/extensions.js';
import { StaticTrustStore } from '../../src/trust/TrustStore.js';
import { getSkiHex } from '../../src/trust/x509-utils.js';
import { AV_REFERENCE_ISSUER_CA_DER_BASE64 } from '../fixtures/av-reference-issuer-ca.js';

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

const ALG = { name: 'ECDSA', hash: 'SHA-256' };
const IAN = '2.5.29.18';
const SKI = '2.5.29.14';
const BASIC_CONSTRAINTS = '2.5.29.19';
const CERTIFICATE_POLICIES = '2.5.29.32';

/** SEQUENCE { INTEGER 5 }: valid DER, but none of these extensions' syntax. */
const UNDECODABLE = new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x05]).buffer;
/** An OCTET STRING whose length runs past the end: no decoder accepts it. */
const TRUNCATED = new Uint8Array([0x04, 0x05, 0x01]).buffer;

const serial = (): string =>
    '01' + crypto.getRandomValues(new Uint8Array(8)).reduce((s, b) => s + b.toString(16).padStart(2, '0'), '');

function malformed(oid: string, critical = false, value: ArrayBuffer = UNDECODABLE): x509.Extension {
    return new x509.Extension(oid, critical, value);
}

async function keys(): Promise<CryptoKeyPair> {
    return (await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
        'sign',
        'verify',
    ])) as CryptoKeyPair;
}

async function caWith(extra: x509.Extension[] = [], { ski = true } = {}) {
    const caKeys = await keys();
    const certificate = await x509.X509CertificateGenerator.createSelfSigned({
        serialNumber: serial(),
        name: `CN=CA ${crypto.randomUUID()}`,
        notBefore: new Date(Date.now() - 1000),
        notAfter: new Date(Date.now() + 864e5),
        signingAlgorithm: ALG,
        keys: caKeys,
        extensions: [
            new x509.BasicConstraintsExtension(true, undefined, true),
            new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
            ...(ski ? [await x509.SubjectKeyIdentifierExtension.create(caKeys.publicKey)] : []),
            ...extra,
        ],
    });
    return { certificate, keys: caKeys };
}

async function leafUnder(ca: { certificate: x509.X509Certificate; keys: CryptoKeyPair }, extra: x509.Extension[] = []) {
    const leafKeys = await keys();
    return x509.X509CertificateGenerator.create({
        serialNumber: serial(),
        subject: `CN=Leaf ${crypto.randomUUID()}`,
        issuer: ca.certificate.subject,
        notBefore: new Date(Date.now() - 1000),
        notAfter: new Date(Date.now() + 864e5),
        signingAlgorithm: ALG,
        publicKey: leafKeys.publicKey,
        signingKey: ca.keys.privateKey,
        extensions: [
            new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
            await x509.AuthorityKeyIdentifierExtension.create(ca.keys.publicKey),
            ...extra,
        ],
    });
}

/** A fresh parse, so no cache from an earlier read is involved. */
const reparse = (cert: x509.X509Certificate) => new x509.X509Certificate(cert.rawData);

describe('extension decoding (EID-216)', () => {
    it('decodes each extension on its own, so one malformed extension does not hide the others', async () => {
        const { certificate } = await caWith([malformed(IAN)]);
        const cert = reparse(certificate);

        // The behaviour this module exists for: the library loses every extension.
        expect(() => cert.extensions).toThrow();
        expect(cert.getExtension(x509.BasicConstraintsExtension)).toBeNull();

        const fresh = reparse(certificate);
        expect(readTypedExtension(fresh, BASIC_CONSTRAINTS, x509.BasicConstraintsExtension)?.ca).toBe(true);
        expect(getSkiHex(fresh)).toMatch(/^[0-9a-f]+$/);
        expect(malformedExtensions(fresh)).toEqual([{ oid: IAN, critical: false, problem: 'undecodable' }]);
        // Read again: still decoded, never reported as absent.
        expect(readTypedExtension(fresh, BASIC_CONSTRAINTS, x509.BasicConstraintsExtension)?.ca).toBe(true);
    });

    it('throws malformed_extension when a malformed extension is read, and never returns it as absent', async () => {
        const { certificate } = await caWith([malformed(IAN)]);
        const cert = reparse(certificate);
        for (let attempt = 0; attempt < 2; attempt += 1) {
            let caught: unknown;
            try {
                readExtension(cert, IAN);
            } catch (error) {
                caught = error;
            }
            expect(caught).toBeInstanceOf(CertificateChainError);
            expect((caught as CertificateChainError).reason).toBe('malformed_extension');
        }
    });

    it.each([
        ['a non-critical IssuerAltName', [malformed(IAN, false)], []],
        ['a critical IssuerAltName', [malformed(IAN, true)], [IAN]],
        ['a non-critical certificatePolicies', [malformed(CERTIFICATE_POLICIES, false)], [CERTIFICATE_POLICIES]],
    ])('tolerates only a malformed non-critical IssuerAltName: %s', async (_label, extra, expected) => {
        const { certificate } = await caWith(extra);
        expect(disqualifyingExtensions(reparse(certificate)).map((e) => e.oid)).toEqual(expected);
    });

    it('refuses a malformed key identifier or CA constraint', async () => {
        const badSki = await caWith([malformed(SKI, false, TRUNCATED)], { ski: false });
        expect(unusableAnchorReason(reparse(badSki.certificate))).toContain(SKI);

        const caKeys = await keys();
        const badBc = await x509.X509CertificateGenerator.createSelfSigned({
            serialNumber: serial(),
            name: `CN=CA ${crypto.randomUUID()}`,
            notBefore: new Date(Date.now() - 1000),
            notAfter: new Date(Date.now() + 864e5),
            signingAlgorithm: ALG,
            keys: caKeys,
            extensions: [malformed(BASIC_CONSTRAINTS, true, TRUNCATED)],
        });
        expect(unusableAnchorReason(reparse(badBc))).toContain(BASIC_CONSTRAINTS);
    });

    it('treats an extension that appears twice as malformed (RFC 5280 §4.2)', async () => {
        const { certificate } = await caWith([new x509.BasicConstraintsExtension(true, undefined, true)]);
        const cert = reparse(certificate);
        expect(malformedExtensions(cert)).toEqual([{ oid: BASIC_CONSTRAINTS, critical: true, problem: 'duplicate' }]);
        expect(() => readExtension(cert, BASIC_CONSTRAINTS)).toThrow(CertificateChainError);
    });

    it('accepts the AV-TL reference issuer CA, whose IssuerAltName is malformed', () => {
        const cert = new x509.X509Certificate(Buffer.from(AV_REFERENCE_ISSUER_CA_DER_BASE64, 'base64'));
        expect(malformedExtensions(cert).map((e) => e.oid)).toEqual([IAN]);
        expect(unusableAnchorReason(cert)).toBeNull();
    });
});

describe('StaticTrustStore with unusable anchors (EID-216)', () => {
    it('keeps every usable anchor and reports the rest instead of throwing', async () => {
        const good = await caWith();
        const badSki = await caWith([malformed(SKI, false, TRUNCATED)], { ski: false });
        const reference = new Uint8Array(Buffer.from(AV_REFERENCE_ISSUER_CA_DER_BASE64, 'base64'));
        const garbage = crypto.getRandomValues(new Uint8Array(64));

        const store = new StaticTrustStore([good.certificate, badSki.certificate, garbage, reference]);

        expect(store.rejectedAnchors.map((r) => r.index)).toEqual([1, 2]);
        expect(store.rejectedAnchors[0]!.subject).toBe(badSki.certificate.subject);
        expect(store.rejectedAnchors[0]!.reason).toContain(SKI);
        expect(store.rejectedAnchors[1]!.reason).toMatch(/not an X\.509 certificate/);
        expect(await store.getAnchors({ issuer: good.certificate.subject })).toHaveLength(1);
        const referenceSubject = new x509.X509Certificate(reference).subject;
        expect(await store.getAnchors({ issuer: referenceSubject })).toHaveLength(1);
        expect(await store.getAnchors({ issuer: badSki.certificate.subject })).toEqual([]);
    });
});

describe('ChainBuilder with malformed extensions (EID-216)', () => {
    it('builds a chain whose leaf carries a malformed non-critical IssuerAltName', async () => {
        const ca = await caWith();
        const leaf = await leafUnder(ca, [malformed(IAN)]);
        const chain = await new ChainBuilder().build(reparse(leaf), [ca.certificate]);
        expect(chain).toHaveLength(2);
    });

    it.each([
        ['a malformed non-critical certificatePolicies', malformed(CERTIFICATE_POLICIES)],
        ['a malformed critical IssuerAltName', malformed(IAN, true)],
    ])('refuses a leaf with %s', async (_label, extension) => {
        const ca = await caWith();
        const leaf = await leafUnder(ca, [extension]);
        const result = new ChainBuilder().build(reparse(leaf), [ca.certificate]);
        await expect(result).rejects.toBeInstanceOf(CertificateChainError);
        await expect(result).rejects.toMatchObject({ reason: expect.stringMatching(/malformed_extension|unrecognised_critical_extension/) });
    });
});

describe('extension reads go through extensions.ts (EID-216)', () => {
    it('no source file reads X509Certificate#extensions or #getExtension directly', async () => {
        const { readdirSync, readFileSync } = await import('node:fs');
        const { join } = await import('node:path');
        const root = join(__dirname, '../../src');
        const files = (readdirSync(root, { recursive: true }) as string[]).filter((f) => f.endsWith('.ts'));
        const offenders = files
            .filter((f) => !f.endsWith('extensions.ts'))
            .filter((f) => /\.getExtensions?\(|\b(?:cert|ca|leaf|issuer|child|candidate)\.extensions\b/.test(readFileSync(join(root, f), 'utf8')));
        expect(offenders).toEqual([]);
    });
});
