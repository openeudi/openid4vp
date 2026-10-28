/** Test issuers for the EU Age Verification profile tests (synthetic IACA → Document Signer chains). */
import { Crypto as PeculiarCrypto } from '@peculiar/webcrypto';

import { StaticTrustStore } from '../../src/trust/TrustStore.js';
import type { TestKeyMaterial } from '../fixtures/crypto-helpers.js';
import { createCa, createLeaf, type GeneratedCa, type Leaf } from '../trust/helpers/synthetic-ca.js';

const peculiar = new PeculiarCrypto();

function uniqueName(role: string): string {
    return `CN=${role} ${crypto.randomUUID()},O=Test Attestation Provider,C=EU`;
}

/** @peculiar/webcrypto keys → Node WebCrypto keys, so the mdoc fixture can sign. */
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

/** Holder device key on Node WebCrypto (synthetic-ca switches @peculiar/x509 to its own provider). */
export async function nodeDeviceKey(): Promise<TestKeyMaterial> {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    return { privateKey: pair.privateKey, publicKey: pair.publicKey, x5cBase64: '', certDerBytes: new Uint8Array() };
}

export async function createIssuer(name: string, ekus: string[]): Promise<{ ca: GeneratedCa; ds: TestKeyMaterial }> {
    const ca = await createCa({
        name: uniqueName(`${name} IACA`),
        pathLenConstraint: 0,
        notBefore: new Date(Date.now() - 365 * 24 * 3600 * 1000),
    });
    const ds = await createLeaf(ca, { name: uniqueName(`${name} DS`), extendedKeyUsages: ekus });
    return { ca, ds: await toKeyMaterial(ds) };
}

export function storeOf(...cas: GeneratedCa[]): StaticTrustStore {
    return new StaticTrustStore(cas.map((ca) => ca.certificate));
}
