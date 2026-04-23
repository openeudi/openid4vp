import { AsnConvert, OctetString } from '@peculiar/asn1-schema';
import {
    CertID,
    OCSPRequest,
    Request,
    TBSRequest,
} from '@peculiar/asn1-ocsp';
import { AlgorithmIdentifier, SubjectPublicKeyInfo } from '@peculiar/asn1-x509';
import type { X509Certificate } from '@peculiar/x509';
import type { Cache } from './Cache.js';
import type { Fetcher } from './Fetcher.js';

export interface OcspClientOptions {
    fetcher?: Fetcher;
    cache?: Cache;
}

/**
 * Private — NOT exported from the package root. Builds OCSP requests, POSTs
 * them to the responder URL via the injected `Fetcher`, parses and verifies
 * `BasicOCSPResponse`. Request-verify logic ships across Tasks 11–16; this
 * module currently exposes `buildRequest` only.
 */
export class OcspClient {
    private readonly fetcher: Fetcher;
    // Wired now, consumed by the caching path added in Task 16.
    // eslint-disable-next-line @typescript-eslint/no-unused-private-class-members
    private readonly cache: Cache | undefined;

    constructor(opts: OcspClientOptions = {}) {
        this.fetcher = opts.fetcher ?? globalThis.fetch.bind(globalThis);
        this.cache = opts.cache;
    }

    /**
     * Build a DER-encoded OCSPRequest for (subjectCert, issuerCert).
     * `optionalSignature` is omitted (RFC 6960 §4.1 — responders MUST accept
     * unsigned requests; signing is an interop footgun).
     *
     * CertID uses SHA-1 by default because every real-world OCSP responder
     * still accepts it (RFC 6960 default). issuerNameHash covers the DER-
     * encoded Name; issuerKeyHash covers the raw BIT STRING value of the
     * issuer's SubjectPublicKeyInfo.subjectPublicKey — NOT the full SPKI.
     */
    async buildRequest(
        subjectCert: X509Certificate,
        issuerCert: X509Certificate
    ): Promise<Uint8Array> {
        const issuerNameDer = new Uint8Array(issuerCert.subjectName.toArrayBuffer());
        const issuerNameHashBytes = new Uint8Array(
            await crypto.subtle.digest('SHA-1', issuerNameDer)
        );

        const issuerSpki = AsnConvert.parse(
            new Uint8Array(issuerCert.publicKey.rawData),
            SubjectPublicKeyInfo
        );
        const issuerKeyBytes = new Uint8Array(issuerSpki.subjectPublicKey);
        const issuerKeyHashBytes = new Uint8Array(
            await crypto.subtle.digest('SHA-1', issuerKeyBytes)
        );

        const certId = new CertID({
            hashAlgorithm: new AlgorithmIdentifier({ algorithm: '1.3.14.3.2.26' /* sha1 */ }),
            issuerNameHash: new OctetString(issuerNameHashBytes),
            issuerKeyHash: new OctetString(issuerKeyHashBytes),
            serialNumber: hexToBigIntBytes(subjectCert.serialNumber).buffer as ArrayBuffer,
        });

        const request = new OCSPRequest({
            tbsRequest: new TBSRequest({
                requestList: [new Request({ reqCert: certId })],
            }),
        });
        return new Uint8Array(AsnConvert.serialize(request));
    }
}

/** Convert a hex string (optionally with leading zeros) into the big-endian BigInteger bytes the ASN.1 layer wants. */
function hexToBigIntBytes(hex: string): Uint8Array {
    const clean = hex.replace(/[^0-9a-fA-F]/g, '');
    const padded = clean.length % 2 === 0 ? clean : '0' + clean;
    const out = new Uint8Array(padded.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(padded.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
}
