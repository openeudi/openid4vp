/**
 * RFC 5280 §4.2: "A certificate-using system MUST reject the certificate if it
 * encounters a critical extension it does not recognize". Regression tests
 * for every certificate of the path, ported from the 2026-10-20 audit probe.
 */

import { webcrypto } from 'node:crypto';
import * as x509 from '@peculiar/x509';
import { describe, expect, it } from 'vitest';

import { CertificateChainError } from '../../src/errors.js';
import { ChainBuilder, RECOGNISED_CRITICAL_EXTENSIONS } from '../../src/trust/ChainBuilder.js';

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

const ALG = { name: 'ECDSA', hash: 'SHA-256' };
const PRIVATE_OID = `1.3.6.1.4.1.${10000 + Math.floor(Math.random() * 90000)}.1`;
const CERTIFICATE_POLICIES = '2.5.29.32';
const POLICY_CONSTRAINTS = '2.5.29.36';
const INHIBIT_ANY_POLICY = '2.5.29.54';
const QC_STATEMENTS = '1.3.6.1.5.5.7.1.3';

const serial = (): string => '01' + crypto.getRandomValues(new Uint8Array(8)).reduce((s, b) => s + b.toString(16).padStart(2, '0'), '');

async function keys(): Promise<CryptoKeyPair> {
    return (await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])) as CryptoKeyPair;
}

/** A DER `NULL` body is enough: the validator must refuse before interpreting it. */
function extension(oid: string, critical: boolean): x509.Extension {
    return new x509.Extension(oid, critical, new Uint8Array([0x05, 0x00]).buffer);
}

interface Placement {
    leaf?: x509.Extension[];
    intermediate?: x509.Extension[];
    root?: x509.Extension[];
}

async function buildChain(extra: Placement = {}): Promise<{ leaf: x509.X509Certificate; inter: x509.X509Certificate; root: x509.X509Certificate }> {
    const now = Date.now();
    const rootKeys = await keys();
    const root = await x509.X509CertificateGenerator.createSelfSigned({
        serialNumber: serial(),
        name: `CN=Root ${crypto.randomUUID()}`,
        notBefore: new Date(now - 1000),
        notAfter: new Date(now + 864e5),
        signingAlgorithm: ALG,
        keys: rootKeys,
        extensions: [
            new x509.BasicConstraintsExtension(true, undefined, true),
            new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
            await x509.SubjectKeyIdentifierExtension.create(rootKeys.publicKey),
            ...(extra.root ?? []),
        ],
    });
    const interKeys = await keys();
    const inter = await x509.X509CertificateGenerator.create({
        serialNumber: serial(),
        subject: `CN=Intermediate ${crypto.randomUUID()}`,
        issuer: root.subject,
        notBefore: new Date(now - 1000),
        notAfter: new Date(now + 864e5),
        signingAlgorithm: ALG,
        publicKey: interKeys.publicKey,
        signingKey: rootKeys.privateKey,
        extensions: [
            new x509.BasicConstraintsExtension(true, 0, true),
            new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign, true),
            await x509.SubjectKeyIdentifierExtension.create(interKeys.publicKey),
            await x509.AuthorityKeyIdentifierExtension.create(root, false),
            ...(extra.intermediate ?? []),
        ],
    });
    const leafKeys = await keys();
    const leaf = await x509.X509CertificateGenerator.create({
        serialNumber: serial(),
        subject: `CN=Leaf ${crypto.randomUUID()}`,
        issuer: inter.subject,
        notBefore: new Date(now - 1000),
        notAfter: new Date(now + 864e5),
        signingAlgorithm: ALG,
        publicKey: leafKeys.publicKey,
        signingKey: interKeys.privateKey,
        extensions: [
            new x509.BasicConstraintsExtension(false, undefined, true),
            new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
            await x509.AuthorityKeyIdentifierExtension.create(inter, false),
            ...(extra.leaf ?? []),
        ],
    });
    return { leaf, inter, root };
}

async function reasonFor(extra: Placement): Promise<string> {
    const { leaf, inter, root } = await buildChain(extra);
    try {
        await new ChainBuilder().build(leaf, [root], [inter]);
        return 'accepted';
    } catch (err) {
        expect(err).toBeInstanceOf(CertificateChainError);
        return (err as CertificateChainError).reason;
    }
}

describe('ChainBuilder — critical extensions (RFC 5280 §4.2)', () => {
    it('rejects an unrecognised critical extension on the leaf', async () => {
        expect(await reasonFor({ leaf: [extension(PRIVATE_OID, true)] })).toBe('unrecognised_critical_extension');
    });

    it('rejects an unrecognised critical extension on an intermediate', async () => {
        expect(await reasonFor({ intermediate: [extension(PRIVATE_OID, true)] })).toBe(
            'unrecognised_critical_extension'
        );
    });

    it.each([
        ['certificatePolicies', CERTIFICATE_POLICIES],
        ['policyConstraints', POLICY_CONSTRAINTS],
        ['inhibitAnyPolicy', INHIBIT_ANY_POLICY],
    ])('rejects critical %s, since policy processing is not implemented', async (_name, oid) => {
        expect(await reasonFor({ intermediate: [extension(oid, true)] })).toBe('unrecognised_critical_extension');
    });

    it('accepts an unrecognised extension that is not critical', async () => {
        expect(
            await reasonFor({ leaf: [extension(PRIVATE_OID, false)], intermediate: [extension(PRIVATE_OID, false)] })
        ).toBe('accepted');
    });

    it('accepts critical qcStatements (seen on a real EU PID provider certificate)', async () => {
        expect(RECOGNISED_CRITICAL_EXTENSIONS.has(QC_STATEMENTS)).toBe(true);
        expect(await reasonFor({ leaf: [extension(QC_STATEMENTS, true)] })).toBe('accepted');
    });

    it('does not apply the rule to the trust anchor, which is configuration rather than part of the path', async () => {
        expect(await reasonFor({ root: [extension(PRIVATE_OID, true)] })).toBe('accepted');
    });

    it('applies the rule to a signer that is itself the listed anchor', async () => {
        const { leaf } = await buildChain({ leaf: [extension(PRIVATE_OID, true)] });
        await expect(new ChainBuilder().build(leaf, [leaf])).rejects.toMatchObject({
            reason: 'unrecognised_critical_extension',
        });
    });
});
