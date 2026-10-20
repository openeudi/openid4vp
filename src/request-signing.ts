import { SignJWT } from 'jose';
import { X509Certificate } from '@peculiar/x509';

import { SignedRequestBuildError } from './errors.js';

const SUPPORTED_SIGNING_ALGS = new Set(['ES256', 'ES384', 'RS256']);

export type RequestSigningAlgorithm = 'ES256' | 'ES384' | 'RS256';
export type RequestClientIdPrefix = 'x509_san_dns' | 'x509_hash';

/**
 * The verifier identity a signed Request Object is built from. Shared by the
 * redirect-flow JAR builder (`createSignedAuthorizationRequest`) and the
 * Digital Credentials API builder (`createDcApiRequest`), so both enforce the
 * same certificate checks.
 */
export interface RequestSignerInput {
    clientIdPrefix?: RequestClientIdPrefix;
    hostname?: string;
    allowSelfSignedCertificate?: boolean;
    signer: CryptoKeyPair;
    signingAlgorithm?: RequestSigningAlgorithm;
    certificateChain: Uint8Array[];
}

export interface ResolvedRequestSigner {
    /** `client_id` including its Client Identifier Prefix. */
    clientId: string;
    signingAlg: RequestSigningAlgorithm;
    /** Standard-base64 DER certificates for the `x5c` JOSE header. */
    x5c: string[];
    privateKey: CryptoKey;
}

/**
 * Cheap input checks that do not touch the certificate. Split from
 * {@link resolveRequestSigner} so callers can keep their historical order of
 * validation errors.
 */
export function validateRequestSignerInput(input: RequestSignerInput): RequestSigningAlgorithm {
    if (input.certificateChain.length === 0) {
        throw new SignedRequestBuildError(
            'empty_cert_chain',
            'certificateChain must contain at least the leaf certificate',
        );
    }

    const signingAlg = input.signingAlgorithm ?? 'ES256';
    if (!SUPPORTED_SIGNING_ALGS.has(signingAlg)) {
        throw new SignedRequestBuildError(
            'unsupported_signing_alg',
            `signingAlgorithm ${signingAlg} is not supported (expected ES256/ES384/RS256)`,
        );
    }
    return signingAlg;
}

/**
 * Validate the verifier's signing identity and derive its `client_id`.
 *
 * Checks that the signing key is bound to the leaf certificate, that a
 * supplied hostname appears in the leaf's SAN DNSNames, that the leaf is not
 * self-signed (unless explicitly allowed), and that a multi-certificate chain
 * does not end in a self-signed trust anchor (`trust_anchor_in_chain`).
 */
export async function resolveRequestSigner(
    input: RequestSignerInput,
    defaultPrefix: RequestClientIdPrefix,
): Promise<ResolvedRequestSigner> {
    const signingAlg = validateRequestSignerInput(input);
    const clientIdPrefix = input.clientIdPrefix ?? defaultPrefix;
    const leafCert = new X509Certificate(toArrayBuffer(input.certificateChain[0]));

    // `x509_san_dns` puts the hostname *in* the client_id, so it is mandatory
    // there. `x509_hash` derives the client_id from the certificate instead and
    // does not need one.
    if (clientIdPrefix === 'x509_san_dns' && !input.hostname) {
        throw new SignedRequestBuildError(
            'missing_hostname',
            'hostname is required for clientIdPrefix "x509_san_dns"',
        );
    }

    // Whenever a hostname IS supplied, bind it to the leaf SAN — for
    // `x509_san_dns` because the client_id asserts it, and for `x509_hash`
    // because silently ignoring a hostname the caller went out of their way to
    // provide would hide a misconfigured certificate.
    if (input.hostname) {
        const sanDnsNames = extractDnsNames(leafCert);
        if (!sanDnsNames.includes(input.hostname)) {
            throw new SignedRequestBuildError(
                'hostname_cert_mismatch',
                `leaf cert SAN DNSName values [${sanDnsNames.join(', ')}] do not include hostname "${input.hostname}"`,
            );
        }
    }

    const signerPublicSpki = new Uint8Array(
        await crypto.subtle.exportKey('spki', input.signer.publicKey),
    );
    const leafSpki = new Uint8Array(leafCert.publicKey.rawData);
    if (!bytesEqual(signerPublicSpki, leafSpki)) {
        throw new SignedRequestBuildError(
            'signing_key_cert_mismatch',
            'signer.publicKey SPKI does not match leaf certificate SPKI',
        );
    }

    // HAIP 1.0 Final requires the verifier certificate to chain to a trust
    // anchor the wallet recognises. A self-signed leaf asserts an identity
    // nothing vouches for, so a wallet enforcing the profile rejects the request
    // object — better to fail here, at build time, than to ship a request no
    // conforming wallet will honour.
    //
    // isSelfSigned() verifies the signature against the certificate's own public
    // key rather than comparing Subject and Issuer DN strings. That distinction
    // matters: GHSA-4c2f-96cf-f5fc was a DN-string-equality bug, and a DN check
    // here would both miss a re-signed certificate and misjudge a legitimate
    // cross-signed one.
    if (input.allowSelfSignedCertificate !== true && (await leafCert.isSelfSigned())) {
        throw new SignedRequestBuildError(
            'self_signed_leaf',
            'leaf certificate is self-signed; HAIP 1.0 Final requires a certificate ' +
                'chaining to a trust anchor. Pass allowSelfSignedCertificate: true to ' +
                'override for local development or tests.',
        );
    }

    // HAIP 1.0 §5: "The X.509 certificate of the trust anchor MUST NOT be
    // included in the x5c JOSE header". A single self-signed certificate is the
    // leaf case handled above.
    if (input.certificateChain.length > 1) {
        const last = new X509Certificate(
            toArrayBuffer(input.certificateChain[input.certificateChain.length - 1]),
        );
        if (await last.isSelfSigned()) {
            throw new SignedRequestBuildError(
                'trust_anchor_in_chain',
                'certificateChain ends in a self-signed (trust anchor) certificate; HAIP 1.0 ' +
                    'forbids the trust anchor in x5c. Pass the leaf and intermediates only.',
            );
        }
    }

    const clientId =
        clientIdPrefix === 'x509_hash'
            ? `x509_hash:${await sha256Base64Url(input.certificateChain[0])}`
            : `x509_san_dns:${input.hostname}`;

    return {
        clientId,
        signingAlg,
        x5c: input.certificateChain.map((der) => bytesToBase64(der)),
        privateKey: input.signer.privateKey,
    };
}

/** Sign a Request Object (RFC 9101) with `typ: oauth-authz-req+jwt` and `x5c`. */
export async function signRequestObject(
    payload: Record<string, unknown>,
    signer: ResolvedRequestSigner,
): Promise<string> {
    return new SignJWT(payload)
        .setProtectedHeader({ typ: 'oauth-authz-req+jwt', alg: signer.signingAlg, x5c: signer.x5c })
        .sign(signer.privateKey);
}

function extractDnsNames(cert: X509Certificate): string[] {
    // The @peculiar/x509 SubjectAlternativeName extension is identified by OID
    // 2.5.29.17. Its `.names.items` (a GeneralNames collection) yields entries
    // with { type, value } — where `type: 'dns'` entries are DNSNames.
    const SAN_OID = '2.5.29.17';
    const ext = cert.extensions.find((e) => e.type === SAN_OID);
    if (!ext) return [];
    // Dynamic narrowing: the extension carries a `names` GeneralNames object.
    const names = (ext as unknown as { names?: { items?: Array<{ type: string; value: string }> } }).names;
    const items = names?.items ?? [];
    return items.filter((e) => e.type === 'dns').map((e) => e.value);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}

// OpenID4VP 1.0 §5.9.3 (referenced by HAIP 1.0 Final for the x509_hash Client
// Identifier Prefix): "the base64url-encoded value of the SHA-256 hash of the
// DER-encoded X.509 certificate" of the leaf cert. Unpadded, per RFC 7515 §2.
async function sha256Base64Url(derCert: Uint8Array): Promise<string> {
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(derCert)));
    return bytesToBase64(digest).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function bytesToBase64(bytes: Uint8Array): string {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
    // @peculiar/x509 expects ArrayBuffer (not ArrayBufferLike). Copy bytes to
    // a fresh ArrayBuffer to satisfy the type and handle any buffer backing.
    const out = new ArrayBuffer(bytes.byteLength);
    new Uint8Array(out).set(bytes);
    return out;
}
