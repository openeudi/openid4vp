import { AsnConvert, OctetString } from '@peculiar/asn1-schema';
import {
    BasicOCSPResponse,
    CertID,
    OCSPRequest,
    OCSPResponse,
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
 * Parsed OCSP response envelope. Holds both the decoded `BasicOCSPResponse`
 * (for verification and verdict extraction) and the raw DER bytes (used by
 * the Task 16 caching path). NOT exported from the package root.
 */
export interface OcspResponseEnvelope {
    basic: BasicOCSPResponse;
    responseDer: Uint8Array;
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

    /**
     * POST a DER-encoded OCSP request to the responder URL, parse the reply,
     * and return the decoded `BasicOCSPResponse` plus the raw DER (for later
     * caching).
     *
     * Throws on non-ok HTTP, on non-successful `responseStatus`, or on any
     * `responseType` other than `id-pkix-ocsp-basic` (1.3.6.1.5.5.7.48.1.1).
     * Signature verification is deferred to `verifyResponse` (Task 13).
     */
    async sendRequest(
        url: string,
        requestDer: Uint8Array
    ): Promise<OcspResponseEnvelope> {
        const response = await this.fetcher(url, {
            method: 'POST',
            headers: { 'content-type': 'application/ocsp-request' },
            body: requestDer,
        });
        if (!response.ok) {
            throw new Error(`OCSP fetch failed: HTTP ${response.status} for ${url}`);
        }
        const responseDer = new Uint8Array(await response.arrayBuffer());
        const parsed = AsnConvert.parse(responseDer, OCSPResponse);
        if (parsed.responseStatus !== 0) {
            throw new Error(
                `OCSP non-successful responseStatus=${parsed.responseStatus} for ${url}`
            );
        }
        if (
            !parsed.responseBytes ||
            parsed.responseBytes.responseType !== '1.3.6.1.5.5.7.48.1.1'
        ) {
            throw new Error(`OCSP response is not id-pkix-ocsp-basic`);
        }
        // `responseBytes.response` is an `OctetString` (ArrayBufferView).
        // Copy through `.buffer` so the DER bytes are unwrapped regardless of
        // the view's byteOffset/byteLength.
        const basic = AsnConvert.parse(
            new Uint8Array(parsed.responseBytes.response.buffer),
            BasicOCSPResponse
        );
        return { basic, responseDer };
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
