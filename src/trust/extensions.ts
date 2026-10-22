import { AsnConvert } from '@peculiar/asn1-schema';
import { Certificate as AsnCertificate } from '@peculiar/asn1-x509';
import { Extension, ExtensionFactory, X509Certificate } from '@peculiar/x509';
import { CertificateChainError } from '../errors.js';

/**
 * Certificate extensions, decoded one at a time.
 *
 * `X509Certificate#extensions` (@peculiar/x509 2.x) decodes every extension on
 * first access and throws if any one of them is malformed; worse, it caches an
 * empty list before decoding, so every later access reports the certificate as
 * having **no extensions at all**. Real trusted-list certificates carry
 * malformed non-critical extensions (the EU age-verification reference issuer
 * CA has an undecodable IssuerAltName), so one such field would either abort
 * a whole trust store or silently strip a CA of its constraints.
 *
 * Every extension read in this package goes through here instead: each
 * extension is decoded on its own, from the raw DER.
 *
 * - Fail closed: a certificate with any malformed or duplicated extension
 *   is refused (`CertificateChainError`, `malformed_extension`), with one
 *   exception, {@link TOLERATED_MALFORMED_EXTENSIONS}.
 * - Reading a malformed extension throws the same error: a constraint that
 *   cannot be read is never treated as absent.
 */

/**
 * Non-critical extensions that may be malformed without making the
 * certificate unusable. Only IssuerAltName: it names the issuer for display
 * and plays no part in path validation, and the EU age-verification reference
 * PKI (AV-TL "Age Verification Issuer CA 01" and its Document Signers) encodes
 * it as a nested Extension instead of GeneralNames. Accepting it is a
 * deliberate exception (owner decision, EID-216) to RFC 5280 §4.2's "MUST
 * process a non-critical extension if it is recognized"; a critical one is
 * still refused.
 */
export const TOLERATED_MALFORMED_EXTENSIONS: ReadonlySet<string> = new Set([
    '2.5.29.18', // issuerAltName
]);

export interface MalformedExtension {
    oid: string;
    critical: boolean;
    /** `undecodable`: the value does not parse; `duplicate`: the OID appears more than once (RFC 5280 §4.2). */
    problem: 'undecodable' | 'duplicate';
}

interface DecodedExtensions {
    byOid: Map<string, Extension>;
    malformed: Map<string, MalformedExtension>;
}

const decodedCache = new WeakMap<X509Certificate, DecodedExtensions>();

function decode(cert: X509Certificate): DecodedExtensions {
    const cached = decodedCache.get(cert);
    if (cached) return cached;

    const byOid = new Map<string, Extension>();
    const malformed = new Map<string, MalformedExtension>();
    const raw = AsnConvert.parse(cert.rawData, AsnCertificate).tbsCertificate.extensions ?? [];
    for (const ext of raw) {
        const oid = ext.extnID;
        if (byOid.has(oid) || malformed.has(oid)) {
            byOid.delete(oid);
            malformed.set(oid, { oid, critical: ext.critical, problem: 'duplicate' });
            continue;
        }
        try {
            byOid.set(oid, ExtensionFactory.create(AsnConvert.serialize(ext)));
        } catch {
            malformed.set(oid, { oid, critical: ext.critical, problem: 'undecodable' });
        }
    }
    const decoded = { byOid, malformed };
    decodedCache.set(cert, decoded);
    return decoded;
}

/**
 * The extension with `oid`, decoded with its registered @peculiar/x509 class
 * (e.g. `BasicConstraintsExtension`), or null when the certificate has none.
 * Throws `CertificateChainError` (`malformed_extension`) when it is present
 * but cannot be decoded, or appears twice.
 */
export function readExtension(cert: X509Certificate, oid: string): Extension | null {
    const { byOid, malformed } = decode(cert);
    const bad = malformed.get(oid);
    if (bad) {
        throw new CertificateChainError(
            `certificate ${cert.subject} has a malformed extension ${oid} (${bad.problem})`,
            { reason: 'malformed_extension' }
        );
    }
    return byOid.get(oid) ?? null;
}

/** {@link readExtension}, narrowed to `type`; null when the decoded extension is not one. */
export function readTypedExtension<T extends Extension>(
    cert: X509Certificate,
    oid: string,
    type: abstract new (...args: never[]) => T
): T | null {
    const ext = readExtension(cert, oid);
    return ext instanceof type ? ext : null;
}

/** Every extension of `cert` that cannot be decoded or is duplicated. */
export function malformedExtensions(cert: X509Certificate): MalformedExtension[] {
    return [...decode(cert).malformed.values()];
}

/** The malformed extensions that make `cert` unusable: all but a non-critical tolerated one. */
export function disqualifyingExtensions(cert: X509Certificate): MalformedExtension[] {
    return malformedExtensions(cert).filter(
        (e) => e.critical || e.problem === 'duplicate' || !TOLERATED_MALFORMED_EXTENSIONS.has(e.oid)
    );
}

/**
 * Why `cert` cannot serve as a trust anchor, or null when it can (see
 * {@link disqualifyingExtensions}). Trust stores skip such a certificate
 * instead of failing every lookup on it.
 */
export function unusableAnchorReason(cert: X509Certificate): string | null {
    let bad: MalformedExtension | undefined;
    try {
        bad = disqualifyingExtensions(cert)[0];
    } catch (error) {
        return `certificate does not parse: ${error instanceof Error ? error.message : String(error)}`;
    }
    return bad ? `malformed extension ${bad.oid} (${bad.problem})` : null;
}
